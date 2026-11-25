package proxytest

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// UDP for the SOCKS5 test server: a UDP ASSOCIATE relay, written apart from
// the product's own so that the two can check each other, and a UDP echo
// server to send datagrams to.

// udpHeader builds the header in front of a relayed datagram. host is a name
// or an address literal.
func udpHeader(host string, port int) []byte {
	b := []byte{0, 0, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b = append(b, 1)
		} else {
			b = append(b, 4)
		}
		b = append(b, ip.AsSlice()...)
	} else {
		b = append(b, 3, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

// splitUDP takes a relayed datagram apart. Fragments are not accepted, and
// neither is anything in the two reserved bytes.
func splitUDP(b []byte) (host string, port int, payload []byte, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", 0, nil, false
	}
	rest := b[4:]
	switch b[3] {
	case 1:
		if len(rest) < 4 {
			return "", 0, nil, false
		}
		host, rest = netip.AddrFrom4([4]byte(rest[:4])).String(), rest[4:]
	case 4:
		if len(rest) < 16 {
			return "", 0, nil, false
		}
		host, rest = netip.AddrFrom16([16]byte(rest[:16])).String(), rest[16:]
	case 3:
		if len(rest) < 1 || rest[0] == 0 || len(rest) < 1+int(rest[0]) {
			return "", 0, nil, false
		}
		host, rest = string(rest[1:1+int(rest[0])]), rest[1+int(rest[0]):]
	default:
		return "", 0, nil, false
	}
	if len(rest) < 2 {
		return "", 0, nil, false
	}
	return host, int(binary.BigEndian.Uint16(rest)), rest[2:], true
}

// retry tells whether reading from a UDP socket is worth another try after
// err. fails counts the errors in a row: one that stays must not turn the
// loop into a busy one.
func retry(err error, fails *int) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	// Windows reports here that an earlier datagram bounced.
	if *fails++; *fails > 8 {
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// UDPTargets lists the destinations of relayed datagrams the way the clients
// named them (names are not resolved), once per association and destination,
// oldest first.
func (s *Server) UDPTargets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.udpTargets...)
}

// Associations is the number of UDP associations granted so far.
func (s *Server) Associations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.assocs
}

// LiveAssociations is the number of UDP associations that are open now.
func (s *Server) LiveAssociations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// CloseAssociations ends every open UDP association the way a server does
// that is restarted: it closes the connections they hang on.
func (s *Server) CloseAssociations() {
	s.mu.Lock()
	for c := range s.live {
		_ = c.Close()
	}
	s.mu.Unlock()
}

// associate serves one UDP association: datagrams of the client that asked
// for it are relayed for as long as the connection c stays open.
func (s *Server) associate(c net.Conn) {
	from := c.RemoteAddr()
	local, _ := c.LocalAddr().(*net.TCPAddr)
	peer, _ := c.RemoteAddr().(*net.TCPAddr)
	var pc *net.UDPConn
	err := errors.New("not a TCP client")
	if local != nil && peer != nil {
		pc, err = net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	}
	if err != nil {
		s.logf("%s %s: UDP association refused: %v", s.opt.Type, from, err)
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if !s.track(pc) {
		return
	}
	defer s.untrack(pc)

	bound := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	host := bound.Addr().Unmap().String()
	if s.opt.UDPAnyAddr {
		host = "0.0.0.0"
	}
	// The answer has the shape of a datagram header: version and "succeeded"
	// take the place of the reserved bytes.
	reply := udpHeader(host, int(bound.Port()))
	reply[0] = 5
	if _, err := c.Write(reply); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	s.mu.Lock()
	s.assocs++
	s.live[c] = struct{}{}
	s.mu.Unlock()
	s.logf("%s %s: UDP association on %s", s.opt.Type, from, bound)

	r := &udpRelay{
		s: s, pc: pc, peer: peer.AddrPort().Addr().Unmap(),
		outs: map[string]*net.UDPConn{},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.run()
	}()
	// Nothing more is said on the connection: it is there to end the association.
	_, _ = io.Copy(io.Discard, c)
	_ = pc.Close()
	<-done
	s.mu.Lock()
	delete(s.live, c)
	s.mu.Unlock()
	s.logf("%s %s: UDP association closed, %d datagrams out, %d back", s.opt.Type, from, r.sent, r.back)
}

// udpRelay is the datagram side of one association.
type udpRelay struct {
	s    *Server
	pc   *net.UDPConn
	peer netip.Addr // datagrams are taken from this address alone
	sent int        // datagrams passed on; only run touches it

	mu     sync.Mutex
	client netip.AddrPort          // whoever sent first
	outs   map[string]*net.UDPConn // by the target as the client names it; nil: not reachable
	back   int                     // datagrams passed back
	wg     sync.WaitGroup
}

func (r *udpRelay) run() {
	defer func() {
		r.mu.Lock()
		for _, out := range r.outs {
			if out != nil {
				_ = out.Close()
			}
		}
		r.mu.Unlock()
		r.wg.Wait()
	}()
	buf := make([]byte, 64<<10)
	fails := 0
	for {
		n, from, err := r.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if !retry(err, &fails) {
				return
			}
			continue
		}
		fails = 0
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from.Addr() != r.peer {
			continue
		}
		r.mu.Lock()
		if !r.client.IsValid() {
			r.client = from
		}
		known := r.client == from
		r.mu.Unlock()
		if !known {
			continue
		}
		host, port, payload, ok := splitUDP(buf[:n])
		if !ok || port == 0 {
			continue
		}
		if out := r.out(host, port); out != nil {
			if _, err := out.Write(payload); err == nil {
				r.sent++
			}
		}
	}
}

// out returns the socket for one destination and opens it when the
// destination is new. Only run calls it.
func (r *udpRelay) out(host string, port int) *net.UDPConn {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	r.mu.Lock()
	out, seen := r.outs[target]
	r.mu.Unlock()
	if seen {
		return out
	}
	r.s.mu.Lock()
	r.s.udpTargets = append(r.s.udpTargets, target)
	r.s.mu.Unlock()

	c, err := r.s.opt.Dial("udp", target)
	if err == nil {
		var ok bool
		if out, ok = c.(*net.UDPConn); !ok {
			_ = c.Close()
			err = errors.New("the dial function gave no UDP socket")
		}
	}
	if err == nil && !r.s.track(out) {
		err = net.ErrClosed
	}
	if err != nil {
		r.s.logf("%s UDP -> %s: %v", r.s.opt.Type, target, err)
		out = nil
	}
	r.mu.Lock()
	r.outs[target] = out
	r.mu.Unlock()
	if out != nil {
		r.wg.Add(1)
		go r.pump(out, host, port)
	}
	return out
}

// pump passes what one destination sends on to the client.
func (r *udpRelay) pump(out *net.UDPConn, host string, port int) {
	defer r.wg.Done()
	defer r.s.untrack(out)
	// A reply names the address it came from, the way real servers do it.
	hdr := udpHeader(host, port)
	if ap := out.RemoteAddr().(*net.UDPAddr).AddrPort(); !r.s.opt.UDPReplyName {
		hdr = udpHeader(ap.Addr().Unmap().String(), int(ap.Port()))
	}
	buf := make([]byte, len(hdr)+64<<10)
	copy(buf, hdr)
	fails := 0
	for {
		n, err := out.Read(buf[len(hdr):])
		if err != nil {
			if !retry(err, &fails) {
				return
			}
			continue
		}
		fails = 0
		r.mu.Lock()
		client := r.client
		r.back++
		r.mu.Unlock()
		_, _ = r.pc.WriteToUDPAddrPort(buf[:len(hdr)+n], client)
	}
}

// UDPEcho is a UDP server that answers every datagram with a tag followed by
// what it received.
type UDPEcho struct {
	pc  *net.UDPConn
	tag string
	wg  sync.WaitGroup

	mu       sync.Mutex
	received int
	sources  []string
	seen     map[netip.AddrPort]bool
}

// StartUDPEcho serves on a free loopback port.
func StartUDPEcho(tag string) (*UDPEcho, error) { return StartUDPEchoOn("127.0.0.1:0", tag) }

// StartUDPEchoOn serves on the given address.
func StartUDPEchoOn(listen, tag string) (*UDPEcho, error) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	e := &UDPEcho{pc: pc, tag: tag, seen: map[netip.AddrPort]bool{}}
	e.wg.Add(1)
	go e.serve()
	return e, nil
}

func (e *UDPEcho) serve() {
	defer e.wg.Done()
	buf := make([]byte, len(e.tag)+64<<10)
	copy(buf, e.tag)
	fails := 0
	for {
		n, from, err := e.pc.ReadFromUDPAddrPort(buf[len(e.tag):])
		if err != nil {
			if !retry(err, &fails) {
				return
			}
			continue
		}
		fails = 0
		src := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		e.mu.Lock()
		e.received++
		if !e.seen[src] {
			e.seen[src] = true
			e.sources = append(e.sources, src.String())
		}
		e.mu.Unlock()
		_, _ = e.pc.WriteToUDPAddrPort(buf[:len(e.tag)+n], from)
	}
}

// Addr is the listening address as host:port.
func (e *UDPEcho) Addr() string { return e.pc.LocalAddr().String() }

// Port is the listening port.
func (e *UDPEcho) Port() int { return e.pc.LocalAddr().(*net.UDPAddr).Port }

// Received is the number of datagrams so far.
func (e *UDPEcho) Received() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.received
}

// Sources lists the addresses datagrams came from, each once, in the order
// of their first appearance.
func (e *UDPEcho) Sources() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.sources...)
}

// Close stops the server.
func (e *UDPEcho) Close() {
	_ = e.pc.Close()
	e.wg.Wait()
}

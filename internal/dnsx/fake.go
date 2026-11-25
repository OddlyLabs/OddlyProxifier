// Package dnsx implements an optional fake-IP DNS server. Applications that
// resolve through it get placeholder addresses from a reserved range; when
// they later connect to such an address the engine maps it back to the
// hostname and lets the proxy resolve it ("resolve hostnames through proxy").
package dnsx

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Fake struct {
	pool     netip.Prefix
	size     uint32
	upstream string

	// Dial opens the socket used to forward queries upstream. The engine
	// sets it so that those queries are not redirected back to this server.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Real, when set, names hosts that get their real answer from upstream
	// instead of a placeholder address.
	Real func(name string) bool

	mu     sync.Mutex
	next   uint32
	byName map[string]netip.Addr
	byIP   map[netip.Addr]string

	conn net.PacketConn
}

func NewFake(cidr, upstream string) (*Fake, error) {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil || !pfx.Addr().Is4() || pfx.Bits() > 30 || pfx.Bits() < 8 {
		return nil, errors.New("fake DNS range must be an IPv4 network between /8 and /30")
	}
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		return nil, errors.New("fake DNS upstream must be host:port")
	}
	return &Fake{
		pool:     pfx.Masked(),
		size:     uint32(1)<<(32-pfx.Bits()) - 2,
		upstream: upstream,
		byName:   map[string]netip.Addr{},
		byIP:     map[netip.Addr]string{},
	}, nil
}

func (f *Fake) Upstream() string { return f.upstream }

// Range is the placeholder network.
func (f *Fake) Range() netip.Prefix { return f.pool }

// Addr is the address the server is listening on, or nil.
func (f *Fake) Addr() net.Addr {
	if f.conn == nil {
		return nil
	}
	return f.conn.LocalAddr()
}

// Contains reports whether ip is a placeholder address.
func (f *Fake) Contains(ip netip.Addr) bool { return f.pool.Contains(ip.Unmap()) }

// Lookup maps a placeholder address back to its hostname.
func (f *Fake) Lookup(ip netip.Addr) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.byIP[ip.Unmap()]
	return h, ok
}

// Assign returns the placeholder for name, allocating one if needed. When
// the pool wraps around the oldest mapping is recycled.
func (f *Fake) Assign(name string) netip.Addr {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip, ok := f.byName[name]; ok {
		return ip
	}
	base := binary.BigEndian.Uint32(f.pool.Addr().AsSlice())
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], base+1+f.next%f.size)
	f.next++
	ip := netip.AddrFrom4(b)
	if old, ok := f.byIP[ip]; ok {
		delete(f.byName, old)
	}
	f.byName[name], f.byIP[ip] = ip, name
	return ip
}

// Listen binds the UDP socket and starts serving.
func (f *Fake) Listen(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	f.conn = pc
	go f.serve()
	return nil
}

func (f *Fake) Close() {
	if f.conn != nil {
		_ = f.conn.Close()
	}
}

func (f *Fake) serve() {
	buf := make([]byte, 4096)
	for {
		n, from, err := f.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := f.answer(q); resp != nil {
				_, _ = f.conn.WriteTo(resp, from)
			}
		}()
	}
}

const (
	typeA     = 1
	typeAAAA  = 28
	typeHTTPS = 65
)

func (f *Fake) answer(q []byte) []byte {
	name, qtype, qend, ok := parseQuestion(q)
	if ok && eligible(name) && (f.Real == nil || !f.Real(name)) {
		switch qtype {
		case typeA:
			return buildReply(q, qend, f.Assign(name))
		case typeAAAA, typeHTTPS:
			// No AAAA / HTTPS records: keep clients on the placeholder A record.
			return buildReply(q, qend, netip.Addr{})
		}
	}
	return f.forward(q)
}

func (f *Fake) forward(q []byte) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dial := f.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	c, err := dial(ctx, "udp", f.upstream)
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// eligible filters out names that must keep resolving for real.
func eligible(name string) bool {
	if !strings.Contains(name, ".") {
		return false
	}
	for _, suffix := range []string{".local", ".lan", ".arpa", ".localhost", ".home", ".internal"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	return true
}

// parseQuestion extracts the single question of a standard query.
func parseQuestion(q []byte) (name string, qtype uint16, end int, ok bool) {
	if len(q) < 12 || q[2]&0xF8 != 0 { // QR=0, opcode=0
		return
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		return
	}
	var labels []string
	i := 12
	for {
		if i >= len(q) {
			return
		}
		l := int(q[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(q) {
			return
		}
		labels = append(labels, string(q[i:i+l]))
		i += l
	}
	if i+4 > len(q) || binary.BigEndian.Uint16(q[i+2:i+4]) != 1 { // class IN
		return
	}
	return strings.ToLower(strings.Join(labels, ".")), binary.BigEndian.Uint16(q[i : i+2]), i + 4, true
}

// buildReply answers with one A record, or with an empty NOERROR when ip is
// the zero Addr.
func buildReply(q []byte, qend int, ip netip.Addr) []byte {
	r := make([]byte, 0, qend+16)
	r = append(r, q[:qend]...)
	r[2] = 0x80 | q[2]&0x01 // QR, keep RD
	r[3] = 0x80             // RA, NOERROR
	binary.BigEndian.PutUint16(r[6:8], 0)
	binary.BigEndian.PutUint16(r[8:10], 0)
	binary.BigEndian.PutUint16(r[10:12], 0)
	if ip.IsValid() {
		binary.BigEndian.PutUint16(r[6:8], 1)
		r = append(r, 0xC0, 0x0C, 0, typeA, 0, 1, 0, 0, 0, 10, 0, 4)
		r = append(r, ip.AsSlice()...)
	}
	return r
}

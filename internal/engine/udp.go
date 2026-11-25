package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/proxy"
	"oddlyproxifier/internal/rules"
)

// UDP for clients of the proxy listener: SOCKS5 UDP ASSOCIATE.
//
// An association belongs to one client and lasts as long as the TCP
// connection it was asked for on. Every destination the client sends to is a
// flow: it is matched against the rules the way a connection is, it is listed
// among the connections, and it ends once it has been silent for a while.
//
// Flows that go out directly share one socket per address family, so that
// the client keeps one source port towards the world. Flows that go through
// a SOCKS5 proxy use an association with that proxy. Other kinds of proxy,
// and chains of several, cannot carry UDP: what the rules send there is
// dropped rather than let out unprotected.

var (
	// udpIdle is how long a flow may stay silent before it ends.
	udpIdle = 90 * time.Second
	// udpRetry is how long a destination that could not be reached is left
	// alone before the next datagram for it starts another attempt.
	udpRetry = 5 * time.Second
	// udpRefused is how long a proxy's refusal to relay UDP is taken for its
	// answer before it is asked again.
	udpRefused = 30 * time.Second
)

const (
	udpMaxFlows = 1024     // destinations one client may talk to at once
	udpQueue    = 32       // datagrams held back while a flow is being set up
	udpMaxSize  = 64 << 10 // no datagram is larger
)

// Stages in the life of a flow.
const (
	flowPending = iota // being set up: datagrams wait
	flowOpen           // relaying
	flowDead           // blocked or failed: datagrams are dropped
	flowEnded          // gone from its association
)

var errAssocClosed = errors.New("the UDP association is closed")

type closerFunc func()

func (f closerFunc) Close() error { f(); return nil }

// flowKey names a destination the way the client does.
type flowKey struct {
	host string     // lower case; empty where the client gave an address
	ip   netip.Addr // set where the client gave an address
	port uint16
}

func (k flowKey) String() string {
	if k.host != "" {
		return net.JoinHostPort(k.host, strconv.Itoa(int(k.port)))
	}
	return netip.AddrPortFrom(k.ip, k.port).String()
}

// udpAssoc is one client's UDP association.
type udpAssoc struct {
	e           *Engine
	ctl         net.Conn     // the association lasts as long as this connection
	pc          *net.UDPConn // where the client sends its datagrams
	who         request      // the client: address and process
	peer        netip.Addr   // the only address datagrams are taken from
	idle, retry time.Duration
	refused     time.Duration // how long a proxy's refusal to relay UDP stands
	done        chan struct{}

	mu     sync.Mutex
	closed bool
	client netip.AddrPort // the client's UDP socket, fixed by its first datagram
	flows  map[flowKey]*udpFlow
	legs   map[string]*udpLeg
	full   bool // the limit on flows has been reported
}

// udpFlow is the traffic of one association with one destination.
type udpFlow struct {
	a   *udpAssoc
	key flowKey
	// named is the destination when the client addressed it by number. Replies
	// carry it as their source, also where it is a fake-DNS placeholder.
	named netip.AddrPort

	last atomic.Int64 // time of the latest datagram, unix nanoseconds

	mu     sync.Mutex
	state  int
	queue  [][]byte       // datagrams waiting for the setup, each with room for a header in front
	st     *state         // the rules the flow was decided under
	s      *session       // set before the flow can be found through a leg
	leg    *udpLeg        // what follows is set when the flow opens
	to     netip.AddrPort // direct: where datagrams go
	remote netip.AddrPort // the far end's address as replies name it, when it is known
	hdr    []byte         // through a proxy: the header in front of every datagram
	until  time.Time      // dead: when the destination may be tried again; zero: not while datagrams keep coming
}

// udpLeg is one outbound socket of an association: either a socket for
// direct traffic or an association with a SOCKS5 proxy.
type udpLeg struct {
	key   string
	ready chan struct{} // closed when the leg is open or has failed
	err   error
	users int // flows holding the leg; guarded by the association's mutex

	// Set while the leg is opened, constant from then on.
	pc    *net.UDPConn
	hop   *proxy.Hop     // nil: direct
	ctl   net.Conn       // the proxy's control connection
	relay netip.AddrPort // where the proxy takes datagrams; pc is connected to it
	only  bool           // everything that arrives belongs to one destination, whatever the proxy calls it
	born  time.Time      // when the leg came up

	mu   sync.Mutex
	dead bool
	// By the far end's address. Where a client reaches one address in several
	// ways (by name and by number), the latest flow gets the replies.
	flows map[netip.AddrPort][]*udpFlow
}

// close shuts the leg down from this side.
func (l *udpLeg) close() {
	l.mu.Lock()
	l.dead = true
	l.mu.Unlock()
	if l.pc != nil {
		_ = l.pc.Close()
	}
	if l.ctl != nil {
		_ = l.ctl.Close()
	}
}

// add makes replies from remote reach f. It fails on a leg that has died.
func (l *udpLeg) add(f *udpFlow, remote netip.AddrPort) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dead {
		return false
	}
	l.flows[remote] = append(l.flows[remote], f)
	return true
}

func (l *udpLeg) remove(f *udpFlow, remote netip.AddrPort) {
	l.mu.Lock()
	defer l.mu.Unlock()
	list := l.flows[remote]
	i := slices.Index(list, f)
	if i < 0 {
		return
	}
	if list = slices.Delete(list, i, i+1); len(list) == 0 {
		delete(l.flows, remote)
	} else {
		l.flows[remote] = list
	}
}

func (l *udpLeg) lookup(remote netip.AddrPort) *udpFlow {
	if l.only {
		remote = netip.AddrPort{} // what such a flow is listed under
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if list := l.flows[remote]; len(list) > 0 {
		return list[len(list)-1]
	}
	return nil
}

// kill marks the leg as dead and returns the flows that were using it. It
// reports false for a leg that was dead already.
func (l *udpLeg) kill() ([]*udpFlow, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dead {
		return nil, false
	}
	l.dead = true
	var list []*udpFlow
	for _, flows := range l.flows {
		list = append(list, flows...)
	}
	return list, true
}

// udpVerdict is a proxy's failure to relay UDP, remembered for a moment.
type udpVerdict struct {
	hop   *proxy.Hop // the verdict is void once the proxy has been redefined
	until time.Time
	err   error
}

// udpDown tells why the proxy h could not relay UDP a moment ago. Until that
// verdict runs out the proxy is not asked again: a program that talks to
// hundreds of destinations would otherwise knock on it once for each.
func (e *Engine) udpDown(h *proxy.Hop) error {
	e.failMu.Lock()
	defer e.failMu.Unlock()
	v, ok := e.noUDP[h.ID()]
	if !ok || v.hop != h || !time.Now().Before(v.until) {
		return nil
	}
	return v.err
}

// setUDPDown records that the proxy h failed to relay UDP, or with a nil
// error that it works.
func (e *Engine) setUDPDown(h *proxy.Hop, err error, d time.Duration) {
	e.failMu.Lock()
	if err == nil {
		delete(e.noUDP, h.ID())
	} else {
		e.noUDP[h.ID()] = udpVerdict{hop: h, until: time.Now().Add(d), err: err}
	}
	e.failMu.Unlock()
}

// ------------------------------------------------------------ association

// serveUDP answers a SOCKS5 UDP ASSOCIATE request and keeps the association
// until the client closes the connection.
func (e *Engine) serveUDP(c net.Conn, br *bufio.Reader, base *request) {
	refuse := func(why error) {
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		e.logf(LevelWarn, "UDP association for %s refused: %v", c.RemoteAddr(), why)
	}
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || !base.src.IsValid() {
		refuse(errors.New("not a TCP client"))
		return
	}
	// On the address the client already reaches us at: whatever stands
	// between the two lets that one through.
	network := "udp4"
	if local.IP.To4() == nil {
		network = "udp6"
	}
	pc, err := net.ListenUDP(network, &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		refuse(err)
		return
	}
	a := &udpAssoc{
		e: e, ctl: c, pc: pc, who: *base, peer: base.src.Addr(),
		idle: udpIdle, retry: udpRetry, refused: udpRefused, done: make(chan struct{}),
		flows: map[flowKey]*udpFlow{}, legs: map[string]*udpLeg{},
	}
	a.who.client = nil
	if !e.addAssoc(a) {
		_ = pc.Close()
		refuse(errors.New("the engine is stopping"))
		return
	}
	bound := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	// The answer has the shape of a datagram header with the version in
	// front: version, "granted", a reserved byte, then type, address and port.
	reply := proxy.AppendUDPAddr(nil, bound)
	reply[0] = 5
	if _, err := c.Write(reply); err != nil {
		a.close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	who := orUnknown(appName(base.app))
	e.logf(LevelDebug, "[%s] UDP association for %s opened on %s", who, base.src, bound)
	go a.serve()
	go a.reap()
	// Nothing more is said on this connection; it is the association's lifeline.
	_, _ = io.Copy(io.Discard, br)
	a.close()
	e.logf(LevelDebug, "[%s] UDP association for %s closed", who, base.src)
}

func (e *Engine) addAssoc(a *udpAssoc) bool {
	e.assocMu.Lock()
	defer e.assocMu.Unlock()
	if e.assocOff {
		return false
	}
	if e.assocs == nil {
		e.assocs = map[*udpAssoc]struct{}{}
	}
	e.assocs[a] = struct{}{}
	return true
}

func (e *Engine) removeAssoc(a *udpAssoc) {
	e.assocMu.Lock()
	delete(e.assocs, a)
	e.assocMu.Unlock()
}

// closeAssocs ends every UDP association. With off set, new ones are refused
// from now on.
func (e *Engine) closeAssocs(off bool) {
	e.assocMu.Lock()
	e.assocOff = off
	list := make([]*udpAssoc, 0, len(e.assocs))
	for a := range e.assocs {
		list = append(list, a)
	}
	e.assocMu.Unlock()
	for _, a := range list {
		a.close()
	}
}

func (a *udpAssoc) close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	flows := make([]*udpFlow, 0, len(a.flows))
	for _, f := range a.flows {
		flows = append(flows, f)
	}
	legs := make([]*udpLeg, 0, len(a.legs))
	for _, l := range a.legs {
		legs = append(legs, l)
	}
	a.mu.Unlock()

	close(a.done)
	_ = a.pc.Close()
	_ = a.ctl.Close()
	for _, f := range flows {
		a.drop(f, StateClosed, nil)
	}
	for _, l := range legs {
		go func() {
			<-l.ready // one that is still being opened closes itself
			l.close()
		}()
	}
	a.e.removeAssoc(a)
}

// context returns a context that ends after d, and earlier when the
// association does.
func (a *udpAssoc) context(d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	go func() {
		select {
		case <-a.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (a *udpAssoc) over() bool {
	select {
	case <-a.done:
		return true
	default:
		return false
	}
}

// serve takes the client's datagrams.
func (a *udpAssoc) serve() {
	const room = proxy.MaxUDPHeader
	buf := make([]byte, room+udpMaxSize)
	fails := 0
	for {
		n, from, err := a.pc.ReadFromUDPAddrPort(buf[room:])
		if err != nil {
			if a.over() || errors.Is(err, net.ErrClosed) {
				return
			}
			// Windows reports here that the client refused an earlier reply.
			// Only an error that stays is worth slowing down for.
			if fails++; fails > 8 {
				time.Sleep(5 * time.Millisecond)
			}
			continue
		}
		fails = 0
		if from.Addr().Unmap() != a.peer {
			continue // not the client the association was made for
		}
		a.mu.Lock()
		if !a.client.IsValid() {
			a.client = from
		}
		known := a.client == from
		a.mu.Unlock()
		if !known {
			continue
		}
		host, ip, port, payload, err := proxy.ParseUDPHeader(buf[room : room+n])
		if err != nil || port == 0 {
			continue
		}
		if f := a.flow(host, ip, uint16(port)); f != nil {
			f.push(buf, room+n-len(payload), room+n)
		}
	}
}

// maybeAddr tells cheaply whether s can be an address literal at all.
func maybeAddr(s string) bool {
	last := s[len(s)-1]
	return last >= '0' && last <= '9' || strings.IndexByte(s, ':') >= 0
}

// flow returns the flow to the given destination and starts one when there
// is none.
func (a *udpAssoc) flow(host string, ip netip.Addr, port uint16) *udpFlow {
	if !ip.IsValid() {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" {
			return nil
		}
		if maybeAddr(host) {
			if lit, err := netip.ParseAddr(host); err == nil {
				host, ip = "", lit.Unmap() // an address spelled out as a name
			}
		}
	}
	key := flowKey{host, ip, port}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	if f := a.flows[key]; f != nil {
		a.mu.Unlock()
		return f
	}
	if len(a.flows) >= udpMaxFlows {
		first := !a.full
		a.full = true
		a.mu.Unlock()
		if first {
			a.e.logf(LevelWarn, "[%s] talks UDP to more than %d destinations at once; further ones wait until others fall silent",
				orUnknown(appName(a.who.app)), udpMaxFlows)
		}
		return nil
	}
	f := &udpFlow{a: a, key: key}
	if ip.IsValid() {
		f.named = netip.AddrPortFrom(ip, port)
	}
	f.last.Store(time.Now().UnixNano())
	a.flows[key] = f
	a.mu.Unlock()
	go a.setup(f)
	return f
}

// reap ends the flows that have been silent for too long, and forgets the
// destinations that were refused once that verdict may have changed.
func (a *udpAssoc) reap() {
	every := min(a.idle, a.retry) / 4
	every = min(max(every, 10*time.Millisecond), 5*time.Second)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		var now time.Time
		select {
		case <-a.done:
			return
		case now = <-t.C:
		}
		a.mu.Lock()
		list := make([]*udpFlow, 0, len(a.flows))
		for _, f := range a.flows {
			list = append(list, f)
		}
		a.mu.Unlock()
		cur := a.e.st.Load()
		for _, f := range list {
			silent := now.Sub(time.Unix(0, f.last.Load())) >= a.idle
			f.mu.Lock()
			state, until, st := f.state, f.until, f.st
			f.mu.Unlock()
			switch {
			case state == flowOpen && silent,
				state == flowDead && st != cur, // the rules have changed since
				state == flowDead && until.IsZero() && silent,
				state == flowDead && !until.IsZero() && !now.Before(until):
				a.drop(f, StateClosed, nil)
			}
		}
	}
}

// drop takes f out of the association. The connection entry of a flow that
// was open, or on its way to that, ends in the given state.
//
// The entry of a flow is finished exactly once: by whoever takes the flow
// out of the two stages in which it has a live one.
func (a *udpAssoc) drop(f *udpFlow, state string, err error) {
	a.mu.Lock()
	if a.flows[f.key] == f {
		delete(a.flows, f.key)
	}
	a.mu.Unlock()

	f.mu.Lock()
	was := f.state
	f.state, f.queue = flowEnded, nil
	s, l, remote := f.s, f.leg, f.remote
	f.mu.Unlock()
	switch was {
	case flowOpen:
		a.release(l, f, remote)
		a.e.finish(s, state, err)
	case flowPending:
		// Being set up: the setup notices and gives back what it holds. Where
		// the entry is not listed yet, the setup closes it as soon as it is.
		if s != nil {
			a.e.finish(s, state, err)
		}
	}
	// Dead: the entry was finished when the flow died.
}

func (a *udpAssoc) toClient(b []byte) {
	a.mu.Lock()
	c := a.client
	a.mu.Unlock()
	if c.IsValid() {
		_, _ = a.pc.WriteToUDPAddrPort(b, c)
	}
}

// ------------------------------------------------------------------- legs

// leg hands out the leg with the given key and opens it when there is none.
// Whoever gets one gives it back with release.
func (a *udpAssoc) leg(key string, open func(l *udpLeg) error) (*udpLeg, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, errAssocClosed
	}
	if l := a.legs[key]; l != nil {
		l.users++
		a.mu.Unlock()
		<-l.ready
		if l.err != nil {
			return nil, l.err
		}
		return l, nil
	}
	l := &udpLeg{key: key, ready: make(chan struct{}), users: 1, flows: map[netip.AddrPort][]*udpFlow{}}
	a.legs[key] = l
	a.mu.Unlock()

	err := open(l)
	a.mu.Lock()
	if a.closed {
		err = errAssocClosed
	}
	if err != nil && a.legs[key] == l {
		delete(a.legs, key)
	}
	a.mu.Unlock()
	if err != nil {
		l.close()
		l.err = err
		close(l.ready)
		return nil, err
	}
	l.born = time.Now()
	close(l.ready)
	go a.pump(l)
	if l.ctl != nil {
		go a.watch(l)
	}
	return l, nil
}

// release gives a leg back. An association with a proxy ends with its last
// flow. The sockets of direct traffic stay, so that the client keeps its
// port towards the world for as long as its association lasts.
func (a *udpAssoc) release(l *udpLeg, f *udpFlow, remote netip.AddrPort) {
	l.remove(f, remote)
	a.mu.Lock()
	l.users--
	gone := l.users == 0 && l.hop != nil
	if gone && a.legs[l.key] == l {
		delete(a.legs, l.key)
	}
	a.mu.Unlock()
	if gone {
		l.close()
	}
}

// directLeg is the socket datagrams to dst leave from without a proxy.
func (a *udpAssoc) directLeg(dst netip.Addr) (*udpLeg, error) {
	key, network, bind := "direct4", "udp4", ":0"
	if !dst.Is4() {
		key, network = "direct6", "udp6"
	}
	if dst.IsLoopback() {
		// Kept apart: a socket that can also be reached from outside is not
		// needed for talking to this machine.
		key, bind = key+"lo", "127.0.0.1:0"
		if !dst.Is4() {
			bind = "[::1]:0"
		}
	}
	return a.leg(key, func(l *udpLeg) error {
		lc := net.ListenConfig{Control: a.e.backend.DialControl()}
		pc, err := lc.ListenPacket(context.Background(), network, bind)
		if err != nil {
			return err
		}
		l.pc = pc.(*net.UDPConn)
		return nil
	})
}

// proxyLeg is an association with the SOCKS5 proxy h. With only set, it is
// one that carries nothing but that flow.
func (a *udpAssoc) proxyLeg(st *state, h *proxy.Hop, only *udpFlow) (*udpLeg, error) {
	key := fmt.Sprintf("proxy %p", h)
	if only != nil {
		key += " " + only.key.String()
	}
	return a.leg(key, func(l *udpLeg) error {
		if err := a.e.udpDown(h); err != nil {
			return err
		}
		ctx, cancel := a.context(st.timeout)
		defer cancel()
		// failed remembers what went wrong, unless all that happened is that
		// the client's association ended meanwhile.
		failed := func(err error) error {
			if a.over() {
				return errAssocClosed
			}
			d := a.retry
			if errors.Is(err, proxy.ErrNoUDP) {
				d = a.refused // an answer, not an accident
			}
			a.e.setUDPDown(h, err, d)
			return err
		}
		c, err := a.e.proxyDial(ctx, "tcp", h.Addr())
		if err != nil {
			if !a.over() {
				a.e.markFailed(h, true)
			}
			return failed(fmt.Errorf("%s: %w", h.Name(), err))
		}
		// Closing the connection is all that gets the handshake out of a read
		// when the client's association ends meanwhile.
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		// A proxy that turns the request down is not a broken one: connections
		// through it still work, so it keeps its place for those.
		relay, err := h.Associate(ctx, c)
		if !stop() && err == nil {
			err = fmt.Errorf("%s (%s): UDP association: %w", h.Name(), h.Type(), ctx.Err())
		}
		if err != nil {
			_ = c.Close()
			return failed(err)
		}
		// Connected: the system then takes datagrams from the relay alone.
		pc, err := a.e.dialer(0).DialContext(ctx, "udp", relay.String())
		if err != nil {
			_ = c.Close()
			return failed(fmt.Errorf("%s: UDP relay %s: %w", h.Name(), relay, err))
		}
		a.e.markFailed(h, false)
		a.e.setUDPDown(h, nil, 0)
		l.pc, l.hop, l.ctl, l.relay, l.only = pc.(*net.UDPConn), h, c, relay, only != nil
		return nil
	})
}

// watch waits for the proxy to end its association, which it does by
// closing the control connection.
func (a *udpAssoc) watch(l *udpLeg) {
	_, _ = io.Copy(io.Discard, l.ctl)
	flows, alive := l.kill()
	if !alive {
		return // closed from this side: with its last flow, or with the client's association
	}
	a.mu.Lock()
	if a.legs[l.key] == l {
		delete(a.legs, l.key)
	}
	a.mu.Unlock()
	l.close()
	err := fmt.Errorf("%s ended the UDP association", l.hop.Name())
	if time.Since(l.born) < a.retry && !a.over() {
		// One that does not last a moment is not asked for again right away.
		a.e.setUDPDown(l.hop, err, a.retry)
	}
	for _, f := range flows {
		a.drop(f, StateFailed, err)
	}
}

// pump passes what arrives on a leg on to the client.
func (a *udpAssoc) pump(l *udpLeg) {
	const room = proxy.MaxUDPHeader
	buf := make([]byte, room+udpMaxSize)
	var scratch [proxy.MaxUDPHeader]byte
	fails := 0
	for {
		n, from, err := l.pc.ReadFromUDPAddrPort(buf[room:])
		if err != nil {
			if a.over() || errors.Is(err, net.ErrClosed) {
				return
			}
			// The system reports here that the other side refused an earlier
			// datagram. Nothing to do about that, and no reason to hold up
			// the flows that share the socket.
			if fails++; fails > 8 {
				time.Sleep(5 * time.Millisecond)
			}
			continue
		}
		fails = 0
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		off, end := room, room+n
		src := from
		if l.hop != nil {
			_, ip, port, payload, err := proxy.ParseUDPHeader(buf[off:end])
			if err != nil {
				continue
			}
			off = end - len(payload)
			src = netip.AddrPortFrom(ip, uint16(port)) // no address: the proxy names the sender
		}
		f := l.lookup(src)
		if f == nil {
			continue // nothing the client has sent to
		}
		start := room
		switch {
		case f.named.IsValid():
			// From where the client sent to, also when that is a placeholder
			// address of the fake DNS.
			hdr := proxy.AppendUDPAddr(scratch[:0], f.named)
			start = off - len(hdr)
			copy(buf[start:], hdr)
		case l.hop == nil:
			hdr := proxy.AppendUDPAddr(scratch[:0], from)
			start = off - len(hdr)
			copy(buf[start:], hdr)
		}
		f.last.Store(time.Now().UnixNano())
		f.s.down.Add(int64(end - off))
		a.toClient(buf[start:end])
	}
}

// ------------------------------------------------------------------- flows

// push takes one datagram of the client: b[off:end] is its payload, and
// what is in front of that may be overwritten.
func (f *udpFlow) push(b []byte, off, end int) {
	f.last.Store(time.Now().UnixNano())
	f.mu.Lock()
	defer f.mu.Unlock()
	switch f.state {
	case flowPending:
		if len(f.queue) < udpQueue {
			d := make([]byte, proxy.MaxUDPHeader+end-off)
			copy(d[proxy.MaxUDPHeader:], b[off:end])
			f.queue = append(f.queue, d)
		}
	case flowOpen:
		f.send(b, off, end)
	}
}

// send relays a datagram on an open flow; f.mu is held.
func (f *udpFlow) send(b []byte, off, end int) {
	var err error
	if f.leg.hop != nil {
		start := off - len(f.hdr)
		copy(b[start:], f.hdr)
		_, err = f.leg.pc.Write(b[start:end])
	} else {
		_, err = f.leg.pc.WriteToUDPAddrPort(b[off:end], f.to)
	}
	if err == nil {
		f.s.up.Add(int64(end - off))
	}
}

// die ends the setup of a flow that will not relay anything. It reports
// false for a flow that was given up in the meantime: its entry among the
// connections is closed already.
func (f *udpFlow) die(until time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != flowPending {
		return false
	}
	f.state, f.until, f.queue = flowDead, until, nil
	return true
}

// setup decides what happens to a new flow and opens its way out.
func (a *udpAssoc) setup(f *udpFlow) {
	e := a.e
	st := e.st.Load()
	f.mu.Lock()
	f.st = st
	pending := f.state == flowPending
	f.mu.Unlock()
	if !pending {
		return // the association ended first
	}

	req := a.who
	req.network = "udp"
	req.host, req.ip, req.port = f.key.host, f.key.ip, int(f.key.port)
	stale := false
	if fd := e.fake.Load(); fd != nil && req.ip.IsValid() && fd.Contains(req.ip) {
		if name, ok := fd.Lookup(req.ip); ok {
			req.host, req.fake = name, true
		} else {
			stale = true
		}
	}

	q := rules.Request{App: req.app, Host: req.host, Port: req.port}
	if !req.fake {
		q.IP = req.ip
	}
	ruleName, action := st.set.Match(q)
	var (
		routes  []route
		planErr error
	)
	if action.Type == config.ActionProxy || action.Type == config.ActionChain {
		routes, planErr = e.plan(st, action)
		// A local proxy program's own datagrams must not be fed back to it.
		if planErr == nil && req.pid != 0 && e.ownsLocalProxy(routes, req.pid) {
			ruleName, action, routes = "(local proxy program)", config.Action{Type: config.ActionDirect}, nil
		}
	}

	// Closing the entry by hand ends this flow and leaves the others alone.
	req.closer = closerFunc(func() { a.drop(f, StateClosed, nil) })
	s := e.register(&req)
	s.mu.Lock()
	s.info.Rule, s.info.Action = ruleName, action.Type
	s.mu.Unlock()
	f.mu.Lock()
	f.s = s
	pending = f.state == flowPending
	f.mu.Unlock()
	if !pending {
		// Given up before it was listed: nobody else knows of the entry.
		e.finish(s, StateClosed, nil)
		return
	}

	// fail ends the setup. With final set there is no point in another try
	// for as long as the rules stay what they are.
	fail := func(err error, final bool) {
		var until time.Time
		if !final {
			until = time.Now().Add(a.retry)
		}
		switch {
		case !f.die(until):
			// Given up while it was being set up, and its entry closed with that.
		case a.over():
			e.finish(s, StateClosed, nil) // the client is leaving: nothing went wrong
		default:
			e.finish(s, StateFailed, err)
		}
	}
	switch {
	case stale:
		fail(errors.New("unknown fake DNS address (stale DNS cache?)"), false)
		return
	case planErr != nil:
		fail(planErr, true)
		return
	case action.Type == config.ActionBlock:
		if f.die(time.Time{}) {
			e.finish(s, StateBlocked, nil)
		}
		return
	}

	ctx, cancel := a.context(st.timeout)
	defer cancel()
	resolve := func() (netip.Addr, error) {
		if req.ip.IsValid() && !req.fake {
			return req.ip, nil
		}
		ip, err := e.lookupIP(ctx, "ip", req.host)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("resolve %s: %w", req.host, err)
		}
		s.mu.Lock()
		s.info.IP = ip.String()
		s.mu.Unlock()
		return ip, nil
	}
	who := orUnknown(appName(req.app))

	if action.Type == config.ActionDirect {
		ip, err := resolve()
		if err != nil {
			fail(err, false)
			return
		}
		l, err := a.directLeg(ip)
		if err != nil {
			fail(err, false)
			return
		}
		to := netip.AddrPortFrom(ip, uint16(req.port))
		started, err := a.start(f, l, to, to, nil, "")
		if err != nil {
			fail(err, false)
			return
		}
		if started {
			e.stats.direct.Add(1)
			e.logf(LevelInfo, "[%s] %s open directly (rule: %s)", who, s.target(), ruleName)
		}
		return
	}

	// Through a proxy. It is asked for the name where there is one and it may
	// be resolved there, the same as for connections.
	target := req.host
	var remote netip.AddrPort
	if target == "" || st.prof.DNS.Mode == config.DNSLocal || st.local.Match(target, netip.Addr{}) {
		ip, err := resolve()
		if err != nil {
			fail(err, false)
			return
		}
		remote = netip.AddrPortFrom(ip, uint16(req.port))
		target = ip.WithZone("").String()
	}
	hdr, err := proxy.AppendUDPHeader(nil, target, req.port)
	if err != nil {
		fail(err, true)
		return
	}
	var errs []string
	again := false // something failed that may work the next time
	for _, r := range routes {
		if len(r.hops) != 1 {
			errs = append(errs, fmt.Sprintf("%s: a chain of several proxies %v", r.label(), proxy.ErrNoUDP))
			continue
		}
		h := r.hops[0]
		if h.Type() != config.TypeSOCKS5 {
			errs = append(errs, fmt.Sprintf("%s (%s) %v", h.Name(), h.Type(), proxy.ErrNoUDP))
			continue
		}
		// The proxy does not say which name a reply belongs to. A flow to a
		// name therefore gets an association of its own.
		var only *udpFlow
		if !remote.IsValid() {
			only = f
		}
		l, err := a.proxyLeg(st, h, only)
		if err != nil {
			errs = append(errs, err.Error())
			again = again || !errors.Is(err, proxy.ErrNoUDP)
			continue
		}
		started, err := a.start(f, l, l.relay, remote, hdr, r.label())
		if err != nil {
			errs = append(errs, err.Error())
			again = true
			continue
		}
		if started {
			e.stats.proxied.Add(1)
			e.logf(LevelInfo, "[%s] %s open through %s (rule: %s)", who, s.target(), r.label(), ruleName)
		}
		return
	}
	fail(errors.New(strings.Join(errs, "; ")), !again)
}

// start puts a flow whose way out is open into service and sends what has
// been waiting. It reports false for a flow that was given up in the
// meantime; its entry among the connections is closed already. Unless the
// flow is started, the leg is given back.
func (a *udpAssoc) start(f *udpFlow, l *udpLeg, to, remote netip.AddrPort, hdr []byte, via string) (bool, error) {
	f.mu.Lock()
	if f.state != flowPending {
		// The association is gone, or the entry was closed by hand.
		f.mu.Unlock()
		a.release(l, f, remote)
		return false, nil
	}
	// Listed on the leg only now: a flow that was given up must not take the
	// replies meant for the one that came after it.
	if !l.add(f, remote) {
		f.mu.Unlock()
		a.release(l, f, remote)
		if l.hop == nil {
			return false, errAssocClosed // nothing else closes the sockets of direct traffic
		}
		return false, fmt.Errorf("%s ended the UDP association", l.hop.Name())
	}
	s := f.s
	s.mu.Lock()
	s.info.State, s.info.Via = StateOpen, via
	s.mu.Unlock()
	f.leg, f.to, f.remote, f.hdr = l, to, remote, hdr
	f.state = flowOpen
	queue := f.queue
	f.queue = nil
	for _, d := range queue {
		f.send(d, proxy.MaxUDPHeader, len(d))
	}
	f.mu.Unlock()
	return true, nil
}

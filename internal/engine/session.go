package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/netx"
	"oddlyproxifier/internal/procinfo"
	"oddlyproxifier/internal/proxy"
	"oddlyproxifier/internal/rules"
	"oddlyproxifier/internal/sniff"
)

const (
	recentMax   = 300
	failPenalty = 30 * time.Second
)

// sniffTimeout is how long a transparent connection may wait for the client's
// first bytes before it is routed without a hostname.
var sniffTimeout = 300 * time.Millisecond

// Ports of protocols where the server speaks first: waiting there for client
// bytes would only delay the connection.
var serverFirstPorts = map[int]bool{
	21: true, 22: true, 23: true, 25: true, 110: true, 119: true, 143: true,
	587: true, 2525: true, 3306: true, 5900: true, 6667: true,
}

// Connection states.
const (
	StateConnecting = "connecting"
	StateOpen       = "open"
	StateClosed     = "closed"
	StateFailed     = "failed"
	StateBlocked    = "blocked"
)

// ConnInfo is the public view of one connection.
type ConnInfo struct {
	ID      uint64 `json:"id"`
	Start   int64  `json:"start"` // unix milliseconds
	End     int64  `json:"end,omitempty"`
	Inbound string `json:"inbound"`           // transparent | socks5 | socks4 | http
	Network string `json:"network,omitempty"` // "udp" for the datagrams of a UDP association; empty: TCP
	PID     uint32 `json:"pid,omitempty"`
	App     string `json:"app"`
	AppPath string `json:"app_path,omitempty"`
	Source  string `json:"source"`
	Host    string `json:"host,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port"`
	Rule    string `json:"rule"`
	Action  string `json:"action"` // direct | block | proxy | chain
	Via     string `json:"via,omitempty"`
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
}

type session struct {
	mu       sync.Mutex
	info     ConnInfo
	up, down atomic.Int64
	// Closing these ends the connection. For the datagrams of a UDP
	// association there is no connection to close: client then takes the one
	// destination out of the association.
	client io.Closer
	remote io.Closer
}

func (s *session) snapshot() ConnInfo {
	s.mu.Lock()
	ci := s.info
	s.mu.Unlock()
	ci.Up, ci.Down = s.up.Load(), s.down.Load()
	return ci
}

func (s *session) setHost(h string) {
	s.mu.Lock()
	if s.info.Host == "" {
		s.info.Host = h
	}
	s.mu.Unlock()
}

func (s *session) target() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.info.Host
	if h == "" {
		h = s.info.IP
	}
	t := net.JoinHostPort(h, strconv.Itoa(s.info.Port))
	if s.info.Network != "" {
		t = s.info.Network + " " + t
	}
	return t
}

type stats struct {
	total, direct, proxied, blocked, failed, stray atomic.Int64
	up, down                                       atomic.Int64 // finished connections
}

type StatsSnapshot struct {
	Total   int64 `json:"total"`
	Active  int64 `json:"active"`
	Direct  int64 `json:"direct"`
	Proxied int64 `json:"proxied"`
	Blocked int64 `json:"blocked"`
	Failed  int64 `json:"failed"`
	Up      int64 `json:"up"`
	Down    int64 `json:"down"`
}

func (e *Engine) snapshotStats() StatsSnapshot {
	s := StatsSnapshot{
		Total: e.stats.total.Load(), Direct: e.stats.direct.Load(), Proxied: e.stats.proxied.Load(),
		Blocked: e.stats.blocked.Load(), Failed: e.stats.failed.Load(),
		Up: e.stats.up.Load(), Down: e.stats.down.Load(),
	}
	e.sessMu.Lock()
	for _, x := range e.sessions {
		s.Active++
		s.Up += x.up.Load()
		s.Down += x.down.Load()
	}
	e.sessMu.Unlock()
	return s
}

// Connections returns the live connections and the most recently finished
// ones, both oldest first.
func (e *Engine) Connections() (active, recent []ConnInfo) {
	e.sessMu.Lock()
	list := make([]*session, 0, len(e.sessions))
	for _, s := range e.sessions {
		list = append(list, s)
	}
	recent = append([]ConnInfo{}, e.recent...)
	e.sessMu.Unlock()
	active = make([]ConnInfo, 0, len(list))
	for _, s := range list {
		active = append(active, s.snapshot())
	}
	sortByID(active)
	return active, recent
}

func sortByID(l []ConnInfo) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j-1].ID > l[j].ID; j-- {
			l[j-1], l[j] = l[j], l[j-1]
		}
	}
}

// CloseConn terminates one live connection.
func (e *Engine) CloseConn(id uint64) bool {
	e.sessMu.Lock()
	s := e.sessions[id]
	e.sessMu.Unlock()
	if s == nil {
		return false
	}
	s.kill()
	return true
}

func (e *Engine) closeAll() {
	e.sessMu.Lock()
	list := make([]*session, 0, len(e.sessions))
	for _, s := range e.sessions {
		list = append(list, s)
	}
	e.sessMu.Unlock()
	for _, s := range list {
		s.kill()
	}
}

// CloseAll terminates every live connection.
func (e *Engine) CloseAll() { e.closeAll() }

func (s *session) kill() {
	s.mu.Lock()
	c, r := s.client, s.remote
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	if r != nil {
		_ = r.Close()
	}
}

// request is one connection waiting for a routing decision.
type request struct {
	inbound string
	network string // "udp" for the datagrams of a UDP association
	client  net.Conn
	closer  io.Closer // ends the entry where there is no connection of its own to close
	src     netip.AddrPort
	pid     uint32
	app     string
	host    string
	ip      netip.Addr
	port    int
	fake    bool // ip is a fake-DNS placeholder and must never be dialed
}

var errBlocked = errors.New("blocked by rule")

func appName(p string) string {
	if p == "" {
		return ""
	}
	return path.Base(strings.ReplaceAll(p, `\`, "/"))
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	t, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := t.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func (e *Engine) register(req *request) *session {
	s := &session{}
	switch {
	case req.client != nil:
		s.client = req.client
	case req.closer != nil:
		s.client = req.closer
	}
	s.info = ConnInfo{
		Start: time.Now().UnixMilli(), Inbound: req.inbound, Network: req.network, PID: req.pid,
		App: appName(req.app), AppPath: req.app, Host: req.host, Port: req.port,
		State: StateConnecting,
	}
	if req.src.IsValid() {
		s.info.Source = req.src.String()
	}
	if req.ip.IsValid() && !req.fake {
		s.info.IP = req.ip.String()
	}
	e.sessMu.Lock()
	e.nextID++
	s.info.ID = e.nextID
	e.sessions[s.info.ID] = s
	e.sessMu.Unlock()
	e.stats.total.Add(1)
	return s
}

// finish moves a session to the finished list.
func (e *Engine) finish(s *session, state string, err error) {
	s.mu.Lock()
	s.info.State = state
	s.info.End = time.Now().UnixMilli()
	if err != nil {
		s.info.Error = err.Error()
	}
	s.mu.Unlock()
	ci := s.snapshot()
	e.sessMu.Lock()
	delete(e.sessions, ci.ID)
	if len(e.recent) >= recentMax {
		e.recent = append(e.recent[:0], e.recent[1:]...)
	}
	e.recent = append(e.recent, ci)
	e.sessMu.Unlock()
	e.stats.up.Add(ci.Up)
	e.stats.down.Add(ci.Down)
	e.traffic.account(ci)

	who := ci.App
	if who == "" {
		who = "?"
	}
	switch state {
	case StateFailed:
		e.stats.failed.Add(1)
		e.logf(LevelWarn, "[%s] %s failed: %v", who, s.target(), err)
	case StateBlocked:
		e.stats.blocked.Add(1)
		e.logf(LevelInfo, "[%s] %s blocked (rule: %s)", who, s.target(), ci.Rule)
	default:
		e.logf(LevelDebug, "[%s] %s closed, %s sent, %s received, %s", who, s.target(),
			fmtBytes(ci.Up), fmtBytes(ci.Down), time.Duration(ci.End-ci.Start)*time.Millisecond)
	}
}

func fmtBytes(n int64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(k*k*k))
}

// route is one way to reach the target: a list of hops, tried as a whole.
type route struct {
	hops []*proxy.Hop
}

func (r route) label() string {
	names := make([]string, len(r.hops))
	for i, h := range r.hops {
		names[i] = h.Name()
	}
	return strings.Join(names, " → ")
}

// plan turns a rule action into the candidate routes, in the order to try.
func (e *Engine) plan(st *state, a config.Action) ([]route, error) {
	switch a.Type {
	case config.ActionProxy:
		h, ok := st.hops[a.Target]
		if !ok {
			return nil, fmt.Errorf("rule refers to unknown proxy %q", a.Target)
		}
		return []route{{[]*proxy.Hop{h}}}, nil
	case config.ActionChain:
		c, ok := st.chains[a.Target]
		if !ok || len(c.hops) == 0 {
			return nil, fmt.Errorf("rule refers to unknown chain %q", a.Target)
		}
		if c.cfg.Type == config.ChainSimple {
			return []route{{c.hops}}, nil
		}
		start := 0
		if c.cfg.Type == config.ChainBalance {
			start = int(c.rr.Add(1)-1) % len(c.hops)
		}
		var good, bad []route
		now := time.Now()
		e.failMu.Lock()
		for i := range c.hops {
			h := c.hops[(start+i)%len(c.hops)]
			if t, ok := e.failed[h.ID()]; ok && now.Sub(t) < failPenalty {
				bad = append(bad, route{[]*proxy.Hop{h}})
			} else {
				good = append(good, route{[]*proxy.Hop{h}})
			}
		}
		e.failMu.Unlock()
		// Proxies that failed a moment ago are only used as a last resort.
		return append(good, bad...), nil
	}
	return nil, fmt.Errorf("unknown action %q", a.Type)
}

func (e *Engine) markFailed(h *proxy.Hop, failed bool) {
	e.failMu.Lock()
	if failed {
		e.failed[h.ID()] = time.Now()
	} else {
		delete(e.failed, h.ID())
	}
	e.failMu.Unlock()
}

// open decides what to do with req and establishes the outbound side.
// On failure the session is already finished.
func (e *Engine) open(st *state, req *request) (*session, net.Conn, error) {
	q := rules.Request{App: req.app, Host: req.host, Port: req.port}
	if !req.fake {
		q.IP = req.ip
	}
	ruleName, action := st.set.Match(q)

	// An application that talks to one of our proxy servers on its own must
	// not be tunnelled through that same server again.
	if req.ip.IsValid() && !req.fake && action.Type != config.ActionBlock &&
		e.isProxyServer(st, netip.AddrPortFrom(req.ip, uint16(req.port))) {
		ruleName, action = "(proxy server)", config.Action{Type: config.ActionDirect}
	}

	var routes []route
	if action.Type == config.ActionProxy || action.Type == config.ActionChain {
		var err error
		if routes, err = e.plan(st, action); err != nil {
			s := e.register(req)
			s.mu.Lock()
			s.info.Rule, s.info.Action = ruleName, action.Type
			s.mu.Unlock()
			e.finish(s, StateFailed, err)
			return nil, nil, err
		}
		// A local proxy program's own outbound connections would otherwise be
		// fed back into itself forever.
		if req.pid != 0 && e.ownsLocalProxy(routes, req.pid) {
			ruleName, action, routes = "(local proxy program)", config.Action{Type: config.ActionDirect}, nil
		}
	}

	s := e.register(req)
	s.mu.Lock()
	s.info.Rule, s.info.Action = ruleName, action.Type
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), st.timeout)
	defer cancel()

	switch action.Type {
	case config.ActionBlock:
		e.finish(s, StateBlocked, nil)
		return nil, nil, errBlocked

	case config.ActionDirect:
		ip := req.ip
		if !ip.IsValid() || req.fake {
			var err error
			if ip, err = e.lookupIP(ctx, "ip", req.host); err != nil {
				err = fmt.Errorf("resolve %s: %w", req.host, err)
				e.finish(s, StateFailed, err)
				return nil, nil, err
			}
			s.mu.Lock()
			s.info.IP = ip.String()
			s.mu.Unlock()
		}
		c, err := e.baseDial(ctx, "tcp", netip.AddrPortFrom(ip, uint16(req.port)).String())
		if err != nil {
			e.finish(s, StateFailed, err)
			return nil, nil, err
		}
		e.stats.direct.Add(1)
		e.attach(s, c)
		e.logf(LevelInfo, "[%s] %s open directly (rule: %s)", orUnknown(s.info.App), s.target(), ruleName)
		return s, c, nil
	}

	// Through a proxy or a chain.
	target := req.host
	if target == "" || st.prof.DNS.Mode == config.DNSLocal || st.local.Match(target, netip.Addr{}) {
		ip := req.ip
		if !ip.IsValid() || req.fake {
			var err error
			if ip, err = e.lookupIP(ctx, "ip", req.host); err != nil {
				err = fmt.Errorf("resolve %s: %w", req.host, err)
				e.finish(s, StateFailed, err)
				return nil, nil, err
			}
			s.mu.Lock()
			s.info.IP = ip.String() // what the proxy is asked to connect to
			s.mu.Unlock()
		}
		target = ip.WithZone("").String()
	}

	var errs []string
	for _, r := range routes {
		actx, acancel := context.WithTimeout(context.Background(), st.timeout)
		c, err := proxy.DialChain(actx, e.proxyDial, r.hops, target, req.port)
		acancel()
		if err == nil {
			if len(r.hops) == 1 {
				e.markFailed(r.hops[0], false)
			}
			e.stats.proxied.Add(1)
			s.mu.Lock()
			s.info.Via = r.label()
			s.mu.Unlock()
			e.attach(s, c)
			e.logf(LevelInfo, "[%s] %s open through %s (rule: %s)", orUnknown(s.info.App), s.target(), r.label(), ruleName)
			return s, c, nil
		}
		errs = append(errs, err.Error())
		if errors.Is(err, proxy.ErrTarget) {
			break // the proxy works, the destination does not: no point in trying others
		}
		if len(r.hops) == 1 {
			e.markFailed(r.hops[0], true)
		}
	}
	err := errors.New(strings.Join(errs, "; "))
	e.finish(s, StateFailed, err)
	return nil, nil, err
}

func orUnknown(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func (e *Engine) attach(s *session, remote net.Conn) {
	s.mu.Lock()
	s.remote = remote
	s.info.State = StateOpen
	s.mu.Unlock()
}

// pipe relays until both directions are done, then finishes the session.
func (e *Engine) pipe(st *state, s *session, client, remote net.Conn) {
	netx.Relay(client, remote, &s.up, &s.down, st.idle)
	_ = client.Close()
	_ = remote.Close()
	e.finish(s, StateClosed, nil)
}

// ownsLocalProxy reports whether pid is the program listening on a proxy
// that lives on this machine.
func (e *Engine) ownsLocalProxy(routes []route, pid uint32) bool {
	for _, r := range routes {
		if len(r.hops) == 0 {
			continue
		}
		h := r.hops[0]
		if !isLocalHost(h.Host()) {
			continue
		}
		if e.listenerPID(uint16(h.Port())) == pid {
			return true
		}
	}
	return false
}

func isLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// ------------------------------------------------------------ transparent

func (e *Engine) serveTransparent(c net.Conn) {
	st := e.st.Load()
	org, err := e.backend.Origin(c)
	if err != nil {
		// Not a redirected connection: somebody connected to the port directly.
		e.stats.stray.Add(1)
		e.logf(LevelDebug, "connection from %s to the transparent port dropped: %v", c.RemoteAddr(), err)
		netx.Reset(c)
		return
	}
	dst := netip.AddrPortFrom(org.Dst.Addr().Unmap(), org.Dst.Port())
	src, _ := addrPort(c.RemoteAddr())
	if int(dst.Port()) == st.prof.Options.TransparentPort {
		if local, ok := addrPort(c.LocalAddr()); dst.Addr().IsLoopback() || ok && local.Addr() == dst.Addr() {
			// Would loop back into this listener.
			e.stats.stray.Add(1)
			if src.Addr().IsLoopback() {
				e.logf(LevelDebug, "connection from %s to the transparent port itself dropped", c.RemoteAddr())
			} else {
				// A redirected connection whose original destination the
				// system did not keep (seen with WSL2 mirrored networking).
				e.noOrigin.Do(func() {
					e.logf(LevelWarn, "the system does not report the original destination of redirected connections "+
						"(e.g. %s): transparent interception cannot work here; use the proxy listener instead", c.RemoteAddr())
				})
			}
			netx.Reset(c)
			return
		}
	}

	req := &request{inbound: "transparent", client: c, src: src, ip: dst.Addr(), port: int(dst.Port()), pid: org.PID}
	if req.pid != 0 {
		req.app = procinfo.PathOf(req.pid)
	} else {
		req.pid, req.app = procinfo.Find(src, dst)
	}

	if f := e.fake.Load(); f != nil && f.Contains(dst.Addr()) {
		name, ok := f.Lookup(dst.Addr())
		if !ok {
			s := e.register(req)
			e.finish(s, StateFailed, errors.New("unknown fake DNS address (stale DNS cache?)"))
			netx.Reset(c)
			return
		}
		req.host, req.fake = name, true
	}

	// Learn the hostname from the first bytes. Waiting for them is only
	// worth it when the name can change the route; otherwise it is picked up
	// in passing, for display.
	var s *session
	if req.host == "" && st.prof.DNS.Sniff {
		_, pre := st.set.Match(rules.Request{App: req.app, IP: req.ip, Port: req.port})
		viaProxy := pre.Type == config.ActionProxy || pre.Type == config.ActionChain
		needed := st.set.HostNames() || viaProxy && st.prof.DNS.Mode != config.DNSLocal
		if needed && !serverFirstPorts[req.port] {
			req.client, req.host = sniff.Peek(c, sniffTimeout)
		} else {
			// Only the relay reads from the client, and it starts after s is set.
			req.client = sniff.Tap(c, func(h string) { s.setHost(h) })
		}
	}

	var remote net.Conn
	if s, remote, err = e.open(st, req); err != nil {
		netx.Reset(c)
		return
	}
	e.pipe(st, s, req.client, remote)
}

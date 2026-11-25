// Package engine is the heart of OddlyProxifier: it accepts connections
// (transparently intercepted ones and explicit SOCKS/HTTP proxy clients),
// decides per rule what to do with each of them and relays the traffic
// directly, through a proxy server or through a proxy chain.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/dnsx"
	"oddlyproxifier/internal/intercept"
	"oddlyproxifier/internal/procinfo"
	"oddlyproxifier/internal/proxy"
	"oddlyproxifier/internal/rules"
)

// Version is the product version, overridable at link time.
var Version = "0.2.0"

// state is an immutable routing snapshot; a profile change swaps in a new one.
type state struct {
	prof    *config.Profile
	set     *rules.Set
	hops    map[string]*proxy.Hop
	chains  map[string]*chainState
	timeout time.Duration
	idle    time.Duration
	local   *rules.HostList // names resolved on this machine
}

type chainState struct {
	cfg  config.Chain
	hops []*proxy.Hop
	rr   atomic.Uint32
}

// part tracks one runtime component (listener set, redirection, ...).
type part struct {
	key    string // configuration it was started with
	active bool
	err    string
	stop   func()
}

func (p *part) shutdown() {
	if p.stop != nil {
		p.stop()
	}
	*p = part{}
}

type Engine struct {
	path    string
	backend intercept.Backend
	started time.Time

	st       atomic.Pointer[state]
	fake     atomic.Pointer[dnsx.Fake]
	resolver atomic.Pointer[net.Resolver]
	editMu   sync.Mutex // serialises read-modify-write changes of the profile

	rtMu        sync.Mutex // serialises profile changes and start/stop
	running     bool
	transparent part
	redirect    part
	inbound     part
	inboundAddr net.Addr
	fakeDNS     part

	// listenerPID tells which process listens on a local TCP port.
	listenerPID func(port uint16) uint32

	sessMu   sync.Mutex
	nextID   uint64
	sessions map[uint64]*session
	recent   []ConnInfo // ring of finished connections, oldest first

	// UDP associations of clients of the proxy listener.
	assocMu  sync.Mutex
	assocs   map[*udpAssoc]struct{}
	assocOff bool // stopping: no new ones

	noOrigin sync.Once // warn once when original destinations are missing

	stats   stats
	traffic traffic
	log     logBuffer

	failMu sync.Mutex
	failed map[string]time.Time  // proxy ID -> last failure
	noUDP  map[string]udpVerdict // proxy ID -> a UDP association that failed a moment ago

	proxyAddrs sync.Map // netip.AddrPort of proxy servers the engine connected to
}

// New creates an engine for the profile stored at path.
func New(path string, prof *config.Profile) (*Engine, error) {
	e := &Engine{
		path:        path,
		backend:     intercept.New(),
		started:     time.Now(),
		sessions:    map[uint64]*session{},
		failed:      map[string]time.Time{},
		noUDP:       map[string]udpVerdict{},
		listenerPID: procinfo.ListenerPID,
	}
	e.traffic.init()
	st, err := e.compile(prof)
	if err != nil {
		return nil, err
	}
	e.st.Store(st)
	e.resolver.Store(net.DefaultResolver)
	return e, nil
}

func (e *Engine) compile(prof *config.Profile) (*state, error) {
	prof = prof.Clone()
	if err := prof.Validate(); err != nil {
		return nil, err
	}
	set, err := rules.Compile(prof)
	if err != nil {
		return nil, err
	}
	local, err := rules.CompileHosts(prof.DNS.LocalNames)
	if err != nil {
		return nil, fmt.Errorf("dns: local names: %w", err)
	}
	st := &state{
		prof:    prof,
		set:     set,
		local:   local,
		hops:    map[string]*proxy.Hop{},
		chains:  map[string]*chainState{},
		timeout: time.Duration(prof.Options.ConnectTimeout) * time.Second,
		idle:    time.Duration(prof.Options.IdleTimeout) * time.Second,
	}
	for _, p := range prof.Proxies {
		h := proxy.NewHop(p)
		h.LookupIPv4 = e.lookupIPv4
		st.hops[p.ID] = h
	}
	for _, c := range prof.Chains {
		cs := &chainState{cfg: c}
		for _, id := range c.Proxies {
			cs.hops = append(cs.hops, st.hops[id])
		}
		st.chains[c.ID] = cs
	}
	return st, nil
}

// lookupIP resolves host with the engine's resolver, which bypasses the
// fake DNS server. network is "ip", "ip4" or "ip6".
func (e *Engine) lookupIP(ctx context.Context, network, host string) (netip.Addr, error) {
	ips, err := e.resolver.Load().LookupNetIP(ctx, network, host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, errors.New("no address found")
	}
	// Prefer IPv4: it is what every proxy protocol supports.
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			return ip.Unmap(), nil
		}
	}
	return ips[0], nil
}

func (e *Engine) lookupIPv4(ctx context.Context, host string) (netip.Addr, error) {
	return e.lookupIP(ctx, "ip4", host)
}

// dialer returns a dialer whose sockets are exempt from interception.
func (e *Engine) dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control:   e.backend.DialControl(),
		Resolver:  e.resolver.Load(),
	}
}

func (e *Engine) baseDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return e.dialer(0).DialContext(ctx, network, addr)
}

// proxyDial is baseDial for the first hop of a chain. It remembers the
// server's address, see isProxyServer.
func (e *Engine) proxyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := e.baseDial(ctx, network, addr)
	if err == nil {
		if ap, ok := addrPort(c.RemoteAddr()); ok && !ap.Addr().IsLoopback() {
			e.proxyAddrs.Store(ap, struct{}{})
		}
	}
	return c, err
}

// Profile returns a copy of the active profile.
func (e *Engine) Profile() *config.Profile { return e.st.Load().prof.Clone() }

// Path is where the profile is stored.
func (e *Engine) Path() string { return e.path }

// InboundAddr is the address the explicit proxy listener is bound to, or nil
// when it is not running.
func (e *Engine) InboundAddr() net.Addr {
	e.rtMu.Lock()
	defer e.rtMu.Unlock()
	return e.inboundAddr
}

// SetProfile validates, activates and persists a new profile. Connections
// that are already open keep their route.
func (e *Engine) SetProfile(prof *config.Profile) error {
	prof = prof.Clone()
	st, err := e.compile(prof)
	if err != nil {
		return err
	}
	e.rtMu.Lock()
	defer e.rtMu.Unlock()
	if e.path != "" {
		if err := config.Save(e.path, st.prof); err != nil {
			return fmt.Errorf("save profile: %w", err)
		}
	}
	e.st.Store(st)
	e.logf(LevelInfo, "profile updated: %d proxies, %d chains, %d rules",
		len(st.prof.Proxies), len(st.prof.Chains), len(st.prof.Rules))
	if e.running {
		e.reconcile()
	}
	return nil
}

// SetIntercept switches interception on or off and keeps the rest of the
// profile as it is.
func (e *Engine) SetIntercept(on bool) error {
	e.editMu.Lock()
	defer e.editMu.Unlock()
	p := e.Profile()
	if p.Options.Intercept == on {
		return nil
	}
	p.Options.Intercept = on
	return e.SetProfile(p)
}

// Start brings up listeners and interception as configured. Components that
// fail to start are reported through Status rather than aborting the engine:
// the UI must stay reachable so that the problem can be fixed.
func (e *Engine) Start() {
	e.rtMu.Lock()
	defer e.rtMu.Unlock()
	if e.running {
		return
	}
	e.running = true
	e.assocMu.Lock()
	e.assocOff = false
	e.assocMu.Unlock()
	// Rules of a previous instance that died without cleaning up.
	_ = e.backend.Reset()
	e.applyLogFile()
	e.logf(LevelInfo, "OddlyProxifier %s started (%s/%s, backend: %s)",
		Version, runtime.GOOS, runtime.GOARCH, e.backend.Name())
	e.startSampler()
	e.reconcile()
}

// Stop removes the redirection and closes all listeners and connections.
func (e *Engine) Stop() {
	e.rtMu.Lock()
	defer e.rtMu.Unlock()
	if !e.running {
		return
	}
	e.running = false
	// Redirection goes first so that nothing new is sent to dying listeners.
	e.redirect.shutdown()
	e.transparent.shutdown()
	e.inbound.shutdown()
	e.inboundAddr = nil
	e.fakeDNS.shutdown()
	e.fake.Store(nil)
	e.closeAssocs(true)
	e.closeAll()
	e.stopSampler()
	e.logf(LevelInfo, "engine stopped")
	_ = e.setLogFile("", "")
}

// applyLogFile opens or closes the log file as the profile says.
func (e *Engine) applyLogFile() {
	o := e.st.Load().prof.Options
	if err := e.setLogFile(o.LogFile, o.LogLevel); err != nil {
		e.logf(LevelError, "log file: %v", err)
	}
}

// reconcile makes the running components match the active profile. A
// component that could not be started the last time is tried again, so that
// saving the profile once more is enough after the cause has been removed.
// rtMu must be held.
func (e *Engine) reconcile() {
	st := e.st.Load()
	o := st.prof.Options
	e.applyLogFile()
	if !o.UDP {
		// Switched off: what is being relayed ends as well.
		e.closeAssocs(false)
	}

	// ---- fake DNS
	fakeKey := ""
	if st.prof.DNS.Fake.Enabled {
		f := st.prof.DNS.Fake
		fakeKey = f.Listen + "|" + f.Range + "|" + f.Upstream
	}
	if e.fakeDNS.key != fakeKey || fakeKey != "" && !e.fakeDNS.active {
		e.fakeDNS.shutdown()
		e.fake.Store(nil)
		e.resolver.Store(net.DefaultResolver)
		e.fakeDNS.key = fakeKey
		if fakeKey != "" {
			f := st.prof.DNS.Fake
			fd, err := dnsx.NewFake(f.Range, f.Upstream)
			if err == nil {
				fd.Dial = e.baseDial
				fd.Real = func(name string) bool { return e.st.Load().local.Match(name, netip.Addr{}) }
				err = fd.Listen(f.Listen)
			}
			if err != nil {
				e.fakeDNS.err = err.Error()
				e.logf(LevelError, "fake DNS: %v", err)
			} else {
				e.fakeDNS.active = true
				e.fakeDNS.stop = fd.Close
				e.fake.Store(fd)
				// The engine itself must keep seeing real addresses.
				up := f.Upstream
				e.resolver.Store(&net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
						d := net.Dialer{Control: e.backend.DialControl()}
						return d.DialContext(ctx, network, up)
					},
				})
				e.logf(LevelInfo, "fake DNS listening on %s (range %s, upstream %s)", f.Listen, f.Range, f.Upstream)
			}
		}
	}

	// ---- explicit proxy listener
	if e.inbound.key != o.Inbound || o.Inbound != "" && !e.inbound.active {
		e.inbound.shutdown()
		e.inboundAddr = nil
		e.inbound.key = o.Inbound
		if o.Inbound != "" {
			ln, err := net.Listen("tcp", o.Inbound)
			if err != nil {
				e.inbound.err = err.Error()
				e.logf(LevelError, "proxy listener %s: %v", o.Inbound, err)
			} else {
				e.inbound.active = true
				e.inboundAddr = ln.Addr()
				e.inbound.stop = func() { _ = ln.Close() }
				go e.acceptLoop(ln, e.serveInbound)
				e.logf(LevelInfo, "SOCKS5/SOCKS4/HTTP proxy listening on %s", ln.Addr())
			}
		}
	}

	// ---- transparent listeners
	tKey := ""
	if o.Intercept {
		tKey = fmt.Sprintf("%d|%v", o.TransparentPort, o.IPv6)
	}
	if e.transparent.key != tKey || tKey != "" && !e.transparent.active {
		e.redirect.shutdown()
		e.transparent.shutdown()
		e.transparent.key = tKey
		if tKey != "" {
			lns, err := e.backend.Listen(o.TransparentPort, o.IPv6)
			if err != nil {
				e.transparent.err = err.Error()
				e.logf(LevelError, "transparent listener: %v", err)
			} else {
				e.transparent.active = true
				e.transparent.stop = func() {
					for _, ln := range lns {
						_ = ln.Close()
					}
				}
				for _, ln := range lns {
					go e.acceptLoop(ln, e.serveTransparent)
				}
			}
		}
	}

	// ---- redirection
	if !e.transparent.active {
		e.redirect.shutdown()
		if o.Intercept {
			e.redirect.err = e.transparent.err
		}
		return
	}
	pol, needed := buildPolicy(st.prof, e.fake.Load())
	if !needed {
		if e.redirect.active {
			e.logf(LevelInfo, "interception idle: no rule sends traffic to a proxy")
		}
		e.redirect.shutdown()
		e.redirect.key = "idle"
		return
	}
	if err := e.backend.Apply(pol); err != nil {
		e.redirect.shutdown()
		e.redirect.err = err.Error()
		e.logf(LevelError, "interception: %v", err)
		return
	}
	if !e.redirect.active {
		mode := "all applications"
		if pol.Mode == intercept.ModeApps {
			mode = fmt.Sprintf("%d application pattern(s)", len(pol.Apps))
		}
		e.logf(LevelInfo, "interception active via %s: %s -> port %d", e.backend.Name(), mode, pol.Port)
	}
	e.redirect.key = "on"
	e.redirect.err = ""
	e.redirect.active = true
	e.redirect.stop = func() {
		if err := e.backend.Stop(); err != nil {
			e.logf(LevelWarn, "stop interception: %v", err)
		}
	}
}

func (e *Engine) acceptLoop(ln net.Listener, serve func(net.Conn)) {
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Out of file descriptors and the like: back off instead of spinning.
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			time.Sleep(delay)
			continue
		}
		delay = 0
		go serve(c)
	}
}

// ---------------------------------------------------------------- status

type PartStatus struct {
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
	Error   string `json:"error,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type Status struct {
	Version     string         `json:"version"`
	OS          string         `json:"os"`
	Arch        string         `json:"arch"`
	PID         int            `json:"pid"`
	Uptime      int64          `json:"uptime"` // seconds
	ProfilePath string         `json:"profile_path"`
	Backend     string         `json:"backend"`
	Elevated    bool           `json:"elevated"`
	Intercept   PartStatus     `json:"intercept"`
	Inbound     PartStatus     `json:"inbound"`
	FakeDNS     PartStatus     `json:"fake_dns"`
	BackendInfo map[string]any `json:"backend_info,omitempty"`
	Stats       StatsSnapshot  `json:"stats"`
}

func (e *Engine) Status() Status {
	st := e.st.Load()
	e.rtMu.Lock()
	s := Status{
		Version: Version, OS: runtime.GOOS, Arch: runtime.GOARCH, PID: os.Getpid(),
		Uptime:      int64(time.Since(e.started).Seconds()),
		ProfilePath: e.path,
		Backend:     e.backend.Name(),
		Elevated:    intercept.IsElevated(),
		Intercept: PartStatus{
			Enabled: st.prof.Options.Intercept, Active: e.redirect.active, Error: e.redirect.err,
		},
		Inbound: PartStatus{
			Enabled: st.prof.Options.Inbound != "", Active: e.inbound.active, Error: e.inbound.err,
			Detail: st.prof.Options.Inbound,
		},
		FakeDNS: PartStatus{
			Enabled: st.prof.DNS.Fake.Enabled, Active: e.fakeDNS.active, Error: e.fakeDNS.err,
			Detail: st.prof.DNS.Fake.Listen,
		},
	}
	if e.redirect.key == "idle" {
		s.Intercept.Detail = "idle: no rule sends traffic to a proxy"
	}
	e.rtMu.Unlock()
	s.BackendInfo = e.backend.Info()
	s.Stats = e.snapshotStats()
	return s
}

// ------------------------------------------------------------ proxy check

type CheckResult struct {
	OK     bool   `json:"ok"`
	Millis int64  `json:"ms"`
	Error  string `json:"error,omitempty"`
	Via    string `json:"via"`
	Target string `json:"target"`
}

// Check opens a tunnel to target through a proxy ("proxy", id) or through a
// chain ("chain", id) of the active profile.
func (e *Engine) Check(ctx context.Context, kind, id, target string) CheckResult {
	st := e.st.Load()
	return e.check(ctx, st, kind, id, target)
}

// CheckProxy tests a proxy definition that is not (yet) part of the profile.
func (e *Engine) CheckProxy(ctx context.Context, p config.Proxy, target string) CheckResult {
	res := CheckResult{Target: target, Via: p.Name}
	h := proxy.NewHop(p)
	h.LookupIPv4 = e.lookupIPv4
	return e.runCheck(ctx, res, []*proxy.Hop{h})
}

func (e *Engine) check(ctx context.Context, st *state, kind, id, target string) CheckResult {
	res := CheckResult{Target: target}
	var hops []*proxy.Hop
	switch kind {
	case "proxy":
		h, ok := st.hops[id]
		if !ok {
			res.Error = "unknown proxy"
			return res
		}
		hops, res.Via = []*proxy.Hop{h}, h.Name()
	case "chain":
		c, ok := st.chains[id]
		if !ok {
			res.Error = "unknown chain"
			return res
		}
		if c.cfg.Type != config.ChainSimple {
			// Redundancy groups are tested member by member by the caller.
			res.Error = "only simple chains can be checked as a whole"
			return res
		}
		hops, res.Via = c.hops, c.cfg.Name
	default:
		res.Error = "unknown kind"
		return res
	}
	return e.runCheck(ctx, res, hops)
}

func (e *Engine) runCheck(ctx context.Context, res CheckResult, hops []*proxy.Hop) CheckResult {
	if _, _, err := net.SplitHostPort(res.Target); err != nil {
		res.Error = "target must be host:port"
		return res
	}
	st := e.st.Load()
	ctx, cancel := context.WithTimeout(ctx, st.timeout)
	defer cancel()
	d, err := proxy.Check(ctx, e.proxyDial, hops, res.Target)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK, res.Millis = true, d.Milliseconds()
	return res
}

// isProxyServer reports whether dst is one of the configured proxy servers.
// Applications that talk to such a server themselves must not be sent
// through it a second time.
func (e *Engine) isProxyServer(st *state, dst netip.AddrPort) bool {
	if _, ok := e.proxyAddrs.Load(dst); ok {
		return true
	}
	for _, p := range st.prof.Proxies {
		if int(dst.Port()) != p.Port {
			continue
		}
		if ip, err := netip.ParseAddr(p.Host); err == nil {
			if ip.Unmap() == dst.Addr() {
				return true
			}
		} else if strings.EqualFold(p.Host, "localhost") && dst.Addr().IsLoopback() {
			return true
		}
	}
	return false
}

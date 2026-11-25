package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/intercept"
	"oddlyproxifier/internal/proxy"
	"oddlyproxifier/internal/proxytest"
)

// fakeBackend stands in for the platform's interception. Tests "redirect" a
// connection by dialing the transparent listener through dial, which records
// where the connection is supposed to have been going.
type fakeBackend struct {
	mu        sync.Mutex
	ln        net.Listener
	origins   map[string]intercept.Origin // client address -> original destination
	policies  []intercept.Policy
	listens   int
	stops     int
	resets    int
	applyErr  error
	listenErr error
}

func (b *fakeBackend) Name() string { return "fake" }

func (b *fakeBackend) Listen(port int, ipv6 bool) ([]net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listenErr != nil {
		return nil, b.listenErr
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b.ln = ln
	b.listens++
	return []net.Listener{ln}, nil
}

func (b *fakeBackend) Apply(p intercept.Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.applyErr != nil {
		return b.applyErr
	}
	b.policies = append(b.policies, p)
	return nil
}

func (b *fakeBackend) Stop() error {
	b.mu.Lock()
	b.stops++
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) Reset() error {
	b.mu.Lock()
	b.resets++
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) Origin(c net.Conn) (intercept.Origin, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.origins[c.RemoteAddr().String()]
	if !ok {
		return intercept.Origin{}, errors.New("not a redirected connection")
	}
	return o, nil
}

func (b *fakeBackend) DialControl() func(network, address string, c syscall.RawConn) error {
	return nil
}

func (b *fakeBackend) Info() map[string]any { return map[string]any{"fake": true} }

// counts returns how often the engine listened, applied a policy and stopped
// the redirection.
func (b *fakeBackend) counts() (listens, applies, stops int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.listens, len(b.policies), b.stops
}

func (b *fakeBackend) lastPolicy(t *testing.T) intercept.Policy {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.policies) == 0 {
		t.Fatal("no policy was applied")
	}
	return b.policies[len(b.policies)-1]
}

func (b *fakeBackend) fail(apply, listen error) {
	b.mu.Lock()
	b.applyErr, b.listenErr = apply, listen
	b.mu.Unlock()
}

// addr is where the transparent listener accepts.
func (b *fakeBackend) addr(t *testing.T) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ln == nil {
		t.Fatal("the transparent listener is not running")
	}
	return b.ln.Addr().String()
}

// dial opens a connection that looks to the engine like one an application
// made to dst and that the system redirected. pid is what the platform
// reports as the owner (0: unknown).
func (b *fakeBackend) dial(t *testing.T, dst string, pid uint32) net.Conn {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock() // the engine cannot ask for the origin before it is recorded
	if b.ln == nil {
		t.Fatal("the transparent listener is not running")
	}
	c, err := net.Dial("tcp", b.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b.origins[c.LocalAddr().String()] = intercept.Origin{Dst: netip.MustParseAddrPort(dst), PID: pid}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// rig is an engine wired to a fake backend, listening on free ports.
type rig struct {
	t  *testing.T
	e  *Engine
	be *fakeBackend
}

// newRig starts an engine. The profile starts out as the default one without
// its rules (they would send every loopback target direct), without
// interception, and with the proxy listener on a free port.
func newRig(t *testing.T, edit func(p *config.Profile), hooks ...func(e *Engine)) *rig {
	t.Helper()
	p := config.Default()
	p.Rules = nil
	p.Options.Inbound = "127.0.0.1:0"
	p.Options.Intercept = false
	if edit != nil {
		edit(p)
	}
	e, err := New("", p)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{origins: map[string]intercept.Origin{}}
	e.backend = be
	// The test process itself listens on the proxy ports. Left alone, every
	// proxied connection it makes would count as a local proxy program's own.
	e.listenerPID = func(uint16) uint32 { return 0 }
	for _, h := range hooks {
		h(e)
	}
	e.Start()
	t.Cleanup(e.Stop)
	return &rig{t: t, e: e, be: be}
}

// port is the port of the engine's proxy listener.
func (r *rig) port() int {
	r.t.Helper()
	a := r.e.InboundAddr()
	if a == nil {
		r.t.Fatal("the proxy listener is not running")
	}
	return a.(*net.TCPAddr).Port
}

func (r *rig) inbound() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(r.port())) }

// tunnel asks the engine's proxy listener for a connection to host:port,
// speaking the given proxy protocol.
func (r *rig) tunnel(typ, host string, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hop := proxy.NewHop(config.Proxy{ID: "engine", Name: "engine", Type: typ, Host: "127.0.0.1", Port: r.port()})
	c, err := proxy.DialChain(ctx, (&net.Dialer{}).DialContext, []*proxy.Hop{hop}, host, port)
	if err == nil {
		r.t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

func (r *rig) mustTunnel(typ, host string, port int) net.Conn {
	r.t.Helper()
	c, err := r.tunnel(typ, host, port)
	if err != nil {
		r.t.Fatalf("%s tunnel to %s:%d: %v", typ, host, port, err)
	}
	return c
}

// raw connects to the proxy listener without speaking any protocol yet.
func (r *rig) raw() net.Conn {
	r.t.Helper()
	c, err := net.Dial("tcp", r.inbound())
	if err != nil {
		r.t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	r.t.Cleanup(func() { _ = c.Close() })
	return c
}

// httpClient returns a client that uses the engine as its HTTP proxy.
func (r *rig) httpClient() *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(&url.URL{Scheme: "http", Host: r.inbound()}),
		ExpectContinueTimeout: 30 * time.Second,
	}
	r.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

// finished waits until exactly n connections have ended and returns them,
// oldest first.
func (r *rig) finished(n int) []ConnInfo {
	r.t.Helper()
	var recent []ConnInfo
	waitFor(r.t, fmt.Sprintf("%d finished connection(s)", n), func() bool {
		_, recent = r.e.Connections()
		return len(recent) >= n
	})
	if len(recent) != n {
		r.t.Fatalf("%d finished connections, want %d: %+v", len(recent), n, recent)
	}
	return recent
}

// live waits until exactly n connections are open and returns them.
func (r *rig) live(n int) []ConnInfo {
	r.t.Helper()
	var active []ConnInfo
	waitFor(r.t, fmt.Sprintf("%d open connection(s)", n), func() bool {
		active, _ = r.e.Connections()
		if len(active) != n {
			return false
		}
		for _, ci := range active {
			if ci.State != StateOpen {
				return false
			}
		}
		return true
	})
	return active
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// roundTrip sends msg and expects it back.
func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v (got %q)", err, buf)
	}
	if string(buf) != msg {
		t.Fatalf("got %q back, want %q", buf, msg)
	}
	_ = c.SetDeadline(time.Time{})
}

// expectClosed checks that the other side ends the connection (cleanly or
// with a reset) rather than leaving it open.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var b [1]byte
	n, err := c.Read(b[:])
	var ne net.Error
	if n != 0 || err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the connection was not closed: read %d byte(s), err %v", n, err)
	}
}

func startEcho(t *testing.T, banner string) *proxytest.Echo {
	t.Helper()
	e, err := proxytest.StartEcho(banner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func startProxy(t *testing.T, o proxytest.Options) *proxytest.Server {
	t.Helper()
	s, err := proxytest.Start(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// refuser is a SOCKS5 proxy that works but reaches nothing.
func refuser(t *testing.T) *proxytest.Server {
	return startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: func(string, string) (net.Conn, error) {
		return nil, errors.New("unreachable")
	}})
}

// broken is a "proxy server" that hangs up on everybody.
type broken struct {
	ln   net.Listener
	hits atomic.Int64
}

func startBroken(t *testing.T) *broken {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &broken{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.hits.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return b
}

func (b *broken) config(id string) config.Proxy {
	return config.Proxy{ID: id, Name: id, Type: config.TypeSOCKS5, Host: "127.0.0.1", Port: b.ln.Addr().(*net.TCPAddr).Port}
}

// rawHTTP is an HTTP server under the test's full control: handle gets every
// request together with the connection and decides what goes back. Returning
// false closes the connection.
type rawHTTP struct {
	ln    net.Listener
	conns atomic.Int64
}

// rawReq is one request a rawHTTP server received.
type rawReq struct {
	c    net.Conn      // the response goes here
	br   *bufio.Reader // what the client sends after this request
	q    *http.Request
	body []byte
	nth  int // number of the request on its connection, from 1
}

// ok answers 200 with the given body and extra header lines.
func (x *rawReq) ok(body string, headers ...string) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	if x.q.Method != http.MethodHead {
		b.WriteString(body)
	}
	_, _ = io.WriteString(x.c, b.String())
}

func startRawHTTP(t *testing.T, handle func(x *rawReq) bool) *rawHTTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rawHTTP{ln: ln}
	var (
		mu   sync.Mutex
		open = map[net.Conn]struct{}{}
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			mu.Lock()
			open[c] = struct{}{}
			mu.Unlock()
			go func() {
				defer func() {
					mu.Lock()
					delete(open, c)
					mu.Unlock()
					_ = c.Close()
				}()
				br := bufio.NewReader(c)
				for nth := 1; ; nth++ {
					q, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					body, err := io.ReadAll(q.Body)
					if err != nil {
						return
					}
					if !handle(&rawReq{c: c, br: br, q: q, body: body, nth: nth}) {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for c := range open {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return s
}

func (s *rawHTTP) addr() string { return s.ln.Addr().String() }
func (s *rawHTTP) port() int    { return s.ln.Addr().(*net.TCPAddr).Port }
func (s *rawHTTP) url() string  { return "http://" + s.addr() + "/" }

// startDNS runs a DNS server that answers every A query with 127.0.0.1 and
// everything else with an empty answer. It returns the server's address.
func startDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			if n < 12 {
				continue
			}
			end := 12 // skip the name of the one question
			for end < n && q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5 // root label, type, class
			if end > n {
				continue
			}
			r := append([]byte(nil), q[:end]...)
			r[2], r[3] = 0x80|q[2]&1, 0x80 // response, recursion available, no error
			copy(r[6:12], []byte{0, 0, 0, 0, 0, 0})
			if q[end-4] == 0 && q[end-3] == 1 { // an A query
				r[7] = 1
				r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 127, 0, 0, 1)
			}
			_, _ = pc.WriteTo(r, from)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// resolveA asks the DNS server at addr for the IPv4 address of name.
func resolveA(t *testing.T, addr, name string) netip.Addr {
	t.Helper()
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("DNS query for %s: %v", name, err)
	}
	if n != len(q)+16 || buf[7] != 1 {
		t.Fatalf("DNS reply for %s: % x", name, buf[:n])
	}
	return netip.AddrFrom4([4]byte(buf[n-4 : n]))
}

// selfName is the file name of the running test binary, which is what the
// engine sees as the application behind the test's own connections.
func selfName(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Base(exe)
}

// ownerKnown reports whether the engine found out which process a loopback
// client belongs to. That has to work where the product is supported; on
// other systems tests that depend on it are skipped.
func ownerKnown(t *testing.T, ci ConnInfo) bool {
	t.Helper()
	if ci.PID != 0 {
		return true
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		t.Errorf("the owner of a local client connection was not found: %+v", ci)
	} else {
		t.Logf("process lookup is not available on %s", runtime.GOOS)
	}
	return false
}

func proxyRule(name, target string, hosts ...string) config.Rule {
	return config.Rule{ID: name, Name: name, Enabled: true, Hosts: hosts,
		Action: config.Action{Type: config.ActionProxy, Target: target}}
}

func blockRule(name string, hosts ...string) config.Rule {
	return config.Rule{ID: name, Name: name, Enabled: true, Hosts: hosts,
		Action: config.Action{Type: config.ActionBlock}}
}

func equalStrings(a, b []string) bool {
	return strings.Join(a, "\x00") == strings.Join(b, "\x00") && len(a) == len(b)
}

func itoa(n int) string { return strconv.Itoa(n) }

// viaEngine opens a tunnel to host:port through the engine's proxy listener
// and then through the given proxy servers, the way an application does that
// has been told about those servers itself.
func (r *rig) viaEngine(host string, port int, then ...config.Proxy) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hops := []*proxy.Hop{proxy.NewHop(config.Proxy{
		ID: "engine", Name: "engine", Type: config.TypeSOCKS5, Host: "127.0.0.1", Port: r.port(),
	})}
	for _, p := range then {
		hops = append(hops, proxy.NewHop(p))
	}
	c, err := proxy.DialChain(ctx, (&net.Dialer{}).DialContext, hops, host, port)
	if err == nil {
		r.t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

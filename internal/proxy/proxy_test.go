package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/proxytest"
)

var allTypes = []string{config.TypeSOCKS5, config.TypeSOCKS4, config.TypeSOCKS4A, config.TypeHTTP, config.TypeHTTPS}

func base(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func start(t *testing.T, o proxytest.Options) *proxytest.Server {
	t.Helper()
	s, err := proxytest.Start(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
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

// roundTrip checks that c is a working tunnel to an echo server.
func roundTrip(t *testing.T, c net.Conn, banner string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	if banner != "" {
		got := make([]byte, len(banner))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != banner {
			t.Fatalf("banner through the tunnel: %q, %v", got, err)
		}
	}
	msg := []byte("hello through the tunnel")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatalf("echo through the tunnel: %q, %v", got, err)
	}
}

func wantTargets(t *testing.T, s *proxytest.Server, want ...string) {
	t.Helper()
	got := s.Targets()
	if len(got) != len(want) {
		t.Errorf("the proxy was asked for %q, want %q", got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("the proxy was asked for %q, want %q", got, want)
			return
		}
	}
}

func TestEveryProtocol(t *testing.T) {
	const banner = "220 ready\r\n" // the server talks first, right behind the proxy's reply
	echo := startEcho(t, banner)
	for _, typ := range allTypes {
		for _, auth := range []bool{false, true} {
			name := typ
			if auth {
				name += " with authentication"
			}
			t.Run(name, func(t *testing.T) {
				o := proxytest.Options{Type: typ}
				if auth {
					o.User, o.Pass = "alice", "s3cret pass:word"
				}
				srv := start(t, o)
				c, err := DialChain(testCtx(t), base, []*Hop{NewHop(srv.Config("p"))}, "127.0.0.1", echo.Port())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				roundTrip(t, c, banner)
				wantTargets(t, srv, echo.Addr())
			})
		}
	}
}

func TestCredentialsNobodyAskedFor(t *testing.T) {
	echo := startEcho(t, "")
	for _, typ := range allTypes {
		srv := start(t, proxytest.Options{Type: typ})
		cfg := srv.Config("p")
		cfg.Username, cfg.Password = "alice", "pw"
		c, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "127.0.0.1", echo.Port())
		if err != nil {
			t.Errorf("%s: %v", typ, err)
			continue
		}
		roundTrip(t, c, "")
		c.Close()
	}
}

// Protocols that can carry a name must leave resolving it to the proxy.
func TestNamesGoToTheProxy(t *testing.T) {
	echo := startEcho(t, "")
	target := fmt.Sprintf("echo.test:%d", echo.Port())
	for _, typ := range []string{config.TypeSOCKS5, config.TypeSOCKS4A, config.TypeHTTP, config.TypeHTTPS} {
		srv := start(t, proxytest.Options{Type: typ, Dial: proxytest.Mapper(map[string]string{target: echo.Addr()})})
		hop := NewHop(srv.Config("p"))
		hop.LookupIPv4 = func(context.Context, string) (netip.Addr, error) {
			t.Errorf("%s: the name was resolved on this side", typ)
			return netip.Addr{}, errors.New("unexpected lookup")
		}
		c, err := DialChain(testCtx(t), base, []*Hop{hop}, "echo.test", echo.Port())
		if err != nil {
			t.Errorf("%s: %v", typ, err)
			continue
		}
		roundTrip(t, c, "")
		c.Close()
		wantTargets(t, srv, target)
	}
}

func TestSOCKS4ResolvesOnThisSide(t *testing.T) {
	echo := startEcho(t, "")
	srv := start(t, proxytest.Options{Type: config.TypeSOCKS4})
	hop := NewHop(srv.Config("p"))
	asked := ""
	hop.LookupIPv4 = func(_ context.Context, host string) (netip.Addr, error) {
		asked = host
		return netip.MustParseAddr("127.0.0.1"), nil
	}
	c, err := DialChain(testCtx(t), base, []*Hop{hop}, "echo.test", echo.Port())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, "")
	c.Close()
	if asked != "echo.test" {
		t.Errorf("looked up %q", asked)
	}
	wantTargets(t, srv, echo.Addr())

	// An address in IPv4-mapped form is still IPv4.
	if c, err = DialChain(testCtx(t), base, []*Hop{hop}, "::ffff:127.0.0.1", echo.Port()); err != nil {
		t.Fatalf("IPv4-mapped target: %v", err)
	}
	roundTrip(t, c, "")
	c.Close()

	hop.LookupIPv4 = func(context.Context, string) (netip.Addr, error) {
		return netip.Addr{}, errors.New("no such host")
	}
	_, err = DialChain(testCtx(t), base, []*Hop{hop}, "echo.test", echo.Port())
	if !errors.Is(err, ErrTarget) || !strings.Contains(err.Error(), "resolve echo.test") {
		t.Errorf("failed lookup: %v", err)
	}
	for _, typ := range []string{config.TypeSOCKS4, config.TypeSOCKS4A} {
		cfg := srv.Config("p")
		cfg.Type = typ
		_, err = DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "2001:db8::1", 80)
		if !errors.Is(err, ErrTarget) || !strings.Contains(err.Error(), "IPv6") {
			t.Errorf("%s with an IPv6 target: %v", typ, err)
		}
	}
}

func TestIPv6Targets(t *testing.T) {
	echo := startEcho(t, "")
	target := fmt.Sprintf("[2001:db8::7]:%d", echo.Port())
	for _, typ := range []string{config.TypeSOCKS5, config.TypeHTTP, config.TypeHTTPS} {
		srv := start(t, proxytest.Options{Type: typ, Dial: proxytest.Mapper(map[string]string{target: echo.Addr()})})
		c, err := DialChain(testCtx(t), base, []*Hop{NewHop(srv.Config("p"))}, "2001:db8::7", echo.Port())
		if err != nil {
			t.Errorf("%s: %v", typ, err)
			continue
		}
		roundTrip(t, c, "")
		c.Close()
		wantTargets(t, srv, target)
	}
}

func TestAuthenticationFailures(t *testing.T) {
	echo := startEcho(t, "")
	cases := []struct {
		name             string
		typ              string
		srvUser, srvPass string
		user, pass       string
		want             string
	}{
		{"SOCKS5 without credentials", config.TypeSOCKS5, "alice", "pw", "", "", "no acceptable authentication method"},
		{"SOCKS5 wrong password", config.TypeSOCKS5, "alice", "pw", "alice", "nope", "authentication failed"},
		{"SOCKS5 wrong user", config.TypeSOCKS5, "alice", "pw", "bob", "pw", "authentication failed"},
		{"SOCKS4 wrong user id", config.TypeSOCKS4, "alice", "", "bob", "", "request rejected (code 0x5D)"},
		{"SOCKS4a without user id", config.TypeSOCKS4A, "alice", "", "", "", "request rejected (code 0x5D)"},
		{"HTTP without credentials", config.TypeHTTP, "alice", "pw", "", "", "proxy authentication required"},
		{"HTTP wrong password", config.TypeHTTP, "alice", "pw", "alice", "nope", "proxy authentication required"},
		{"HTTPS wrong password", config.TypeHTTPS, "alice", "pw", "alice", "nope", "proxy authentication required"},
	}
	for _, c := range cases {
		srv := start(t, proxytest.Options{Type: c.typ, User: c.srvUser, Pass: c.srvPass})
		cfg := srv.Config("p")
		cfg.Username, cfg.Password = c.user, c.pass
		conn, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "127.0.0.1", echo.Port())
		if err == nil {
			conn.Close()
			t.Errorf("%s: the tunnel was opened", c.name)
			continue
		}
		if errors.Is(err, ErrTarget) {
			t.Errorf("%s: counts as a failure of the destination: %v", c.name, err)
		}
		if want := "p (" + c.typ + "): "; !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q, want %q…%q", c.name, err, want, c.want)
		}
	}
	if n := echo.Accepted(); n != 0 {
		t.Errorf("%d connections reached the destination without valid credentials", n)
	}
}

// When the proxy works and the destination does not, trying another proxy
// is pointless; such errors carry ErrTarget.
func TestTargetFailuresAreMarked(t *testing.T) {
	refuse := func(network, addr string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	for _, typ := range allTypes {
		srv := start(t, proxytest.Options{Type: typ, Dial: refuse})
		hops := []*Hop{NewHop(srv.Config("p"))}
		if _, err := DialChain(testCtx(t), base, hops, "192.0.2.1", 80); !errors.Is(err, ErrTarget) {
			t.Errorf("%s, destination refuses: %v", typ, err)
		}
		if typ == config.TypeSOCKS4 {
			continue
		}
		srv = start(t, proxytest.Options{Type: typ, Dial: proxytest.Mapper(nil)})
		hops = []*Hop{NewHop(srv.Config("p"))}
		if _, err := DialChain(testCtx(t), base, hops, "nothere.invalid", 80); !errors.Is(err, ErrTarget) {
			t.Errorf("%s, destination name unknown: %v", typ, err)
		}
	}
}

// canned accepts connections and answers each with the same bytes, whatever
// the client says.
func canned(t *testing.T, reply string) config.Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, reply)
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return config.Proxy{ID: "p", Name: "p", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
}

func TestReplyCodes(t *testing.T) {
	socks5 := func(code byte) string {
		return "\x05\x00\x05" + string([]byte{code}) + "\x00\x01\x00\x00\x00\x00\x00\x00"
	}
	socks4 := func(code byte) string { return "\x00" + string([]byte{code}) + "\x00\x00\x00\x00\x00\x00" }
	status := func(s string) string { return "HTTP/1.1 " + s + "\r\nContent-Length: 0\r\n\r\n" }
	cases := []struct {
		typ    string
		reply  string
		target bool   // the destination is to blame
		want   string // part of the message
	}{
		{config.TypeSOCKS5, socks5(1), false, "general failure"},
		{config.TypeSOCKS5, socks5(2), true, "not allowed by ruleset"},
		{config.TypeSOCKS5, socks5(3), true, "network unreachable"},
		{config.TypeSOCKS5, socks5(4), true, "host unreachable"},
		{config.TypeSOCKS5, socks5(5), true, "connection refused"},
		{config.TypeSOCKS5, socks5(6), true, "TTL expired"},
		{config.TypeSOCKS5, socks5(7), false, "command not supported"},
		{config.TypeSOCKS5, socks5(8), true, "address type not supported"},
		{config.TypeSOCKS5, socks5(0x42), false, "reply code 66"},
		{config.TypeSOCKS5, "\x05\xFF", false, "no acceptable authentication method"},
		{config.TypeSOCKS5, "\x05\x02", false, "server requires authentication"},
		{config.TypeSOCKS5, "HTTP/1.1 400 Bad Request\r\n\r\n", false, "not a SOCKS5 server"},
		{config.TypeSOCKS5, "\x05\x00\x05\x00\x00\x09", false, "bad address type in reply"},
		{config.TypeSOCKS4, socks4(0x5B), true, "rejected or failed"},
		{config.TypeSOCKS4, socks4(0x5C), false, "code 0x5C"},
		{config.TypeSOCKS4A, socks4(0x5D), false, "code 0x5D"},
		{config.TypeHTTP, status("403 Forbidden"), true, "403"},
		{config.TypeHTTP, status("404 Not Found"), true, "404"},
		{config.TypeHTTP, status("502 Bad Gateway"), true, "502"},
		{config.TypeHTTP, status("503 Service Unavailable"), true, "503"},
		{config.TypeHTTP, status("504 Gateway Timeout"), true, "504"},
		{config.TypeHTTP, status("500 Internal Server Error"), false, "500"},
		{config.TypeHTTP, status("407 Proxy Authentication Required"), false, "authentication required"},
		{config.TypeHTTP, status("301 Moved Permanently"), false, "301"},
		{config.TypeHTTP, "SSH-2.0-OpenSSH_9.6\r\n", false, "malformed HTTP"},
	}
	for _, c := range cases {
		cfg := canned(t, c.reply)
		cfg.Type = c.typ
		conn, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "192.0.2.1", 80)
		if err == nil {
			conn.Close()
			t.Errorf("%s, reply %q: no error", c.typ, c.reply)
			continue
		}
		if errors.Is(err, ErrTarget) != c.target || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s, reply %q: %v (blames the destination: %v), want %q (%v)",
				c.typ, c.reply, err, errors.Is(err, ErrTarget), c.want, c.target)
		}
	}
}

// SOCKS5 replies may carry a bound address of any type; all of it has to be
// read, or its tail would end up in the tunnel.
func TestSOCKS5BoundAddressIsConsumed(t *testing.T) {
	replies := map[string]string{
		"IPv4":   "\x05\x00\x05\x00\x00\x01\x0A\x00\x00\x01\x04\x38",
		"IPv6":   "\x05\x00\x05\x00\x00\x04" + strings.Repeat("\x00", 15) + "\x01\x04\x38",
		"domain": "\x05\x00\x05\x00\x00\x03\x09localhost\x04\x38",
	}
	for name, reply := range replies {
		cfg := canned(t, reply+"payload")
		cfg.Type = config.TypeSOCKS5
		c, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "192.0.2.1", 80)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got := make([]byte, 7)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != "payload" {
			t.Errorf("%s: the tunnel starts with %q, %v", name, got, err)
		}
		c.Close()
	}
}

func TestProxyFailuresAreNotTargetFailures(t *testing.T) {
	down := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	hop := NewHop(config.Proxy{ID: "p", Name: "office", Type: config.TypeSOCKS5, Host: "192.0.2.1", Port: 1080})
	_, err := DialChain(testCtx(t), down, []*Hop{hop}, "example.test", 80)
	if err == nil || errors.Is(err, ErrTarget) || !strings.HasPrefix(err.Error(), "office: ") {
		t.Errorf("proxy down: %v", err)
	}

	if _, err := DialChain(testCtx(t), base, nil, "example.test", 80); err == nil {
		t.Error("an empty chain gave a connection")
	}

	cfg := canned(t, "")
	cfg.Type = "socks6"
	if _, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "example.test", 80); err == nil || !strings.Contains(err.Error(), "unknown proxy type") {
		t.Errorf("unknown type: %v", err)
	}

	// What SOCKS5 cannot express is refused at once: the server here never
	// answers, so waiting for it would end in a timeout instead.
	cfg.Type = config.TypeSOCKS5
	long := strings.Repeat("a", 256)
	if _, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, long, 80); err == nil || !strings.Contains(err.Error(), "bad hostname length") {
		t.Errorf("over-long name: %v", err)
	}
	if _, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "", 80); err == nil || !strings.Contains(err.Error(), "bad hostname length") {
		t.Errorf("empty name: %v", err)
	}
	cfg.Username, cfg.Password = "u", long
	if _, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "example.test", 80); err == nil || !strings.Contains(err.Error(), "longer than 255") {
		t.Errorf("over-long password: %v", err)
	}
}

func TestSilentProxyTimesOut(t *testing.T) {
	for _, typ := range allTypes {
		cfg := canned(t, "") // accepts and never answers
		cfg.Type = typ
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		c, err := DialChain(ctx, base, []*Hop{NewHop(cfg)}, "192.0.2.1", 80)
		cancel()
		if err == nil {
			c.Close()
			t.Errorf("%s: a tunnel through a silent server", typ)
			continue
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: gave up only after %v", typ, d)
		}
		if errors.Is(err, ErrTarget) {
			t.Errorf("%s: a silent proxy is blamed on the destination: %v", typ, err)
		}
	}
}

func TestHTTPSVerifiesTheCertificate(t *testing.T) {
	echo := startEcho(t, "")
	srv := start(t, proxytest.Options{Type: config.TypeHTTPS})
	cfg := srv.Config("p")
	cfg.TLSInsecure = false
	_, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "127.0.0.1", echo.Port())
	if err == nil || errors.Is(err, ErrTarget) || !strings.Contains(err.Error(), "tls: ") {
		t.Fatalf("self-signed certificate: %v", err)
	}
	if n := len(srv.Targets()); n != 0 {
		t.Errorf("%d requests were sent over an unverified connection", n)
	}

	// A plain HTTP proxy does not speak TLS at all.
	plain := start(t, proxytest.Options{Type: config.TypeHTTP})
	cfg = plain.Config("p")
	cfg.Type = config.TypeHTTPS
	if _, err := DialChain(testCtx(t), base, []*Hop{NewHop(cfg)}, "127.0.0.1", echo.Port()); err == nil || !strings.Contains(err.Error(), "tls: ") {
		t.Errorf("TLS to a plain HTTP proxy: %v", err)
	}
}

func TestChainOfTwo(t *testing.T) {
	echo := startEcho(t, "")
	first := start(t, proxytest.Options{Type: config.TypeSOCKS5})
	second := start(t, proxytest.Options{Type: config.TypeHTTP, User: "u", Pass: "p"})
	hops := []*Hop{NewHop(first.Config("first")), NewHop(second.Config("second"))}
	c, err := DialChain(testCtx(t), base, hops, "127.0.0.1", echo.Port())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c, "")
	wantTargets(t, first, second.Addr())
	wantTargets(t, second, echo.Addr())
	if echo.Accepted() != 1 {
		t.Errorf("%d connections reached the destination", echo.Accepted())
	}
}

// All five protocols in one chain, each of them once in every position.
func TestChainOfFiveInEveryOrder(t *testing.T) {
	const banner = "hello\n"
	echo := startEcho(t, banner)
	target := fmt.Sprintf("127.0.0.1:%d", echo.Port())
	for rot := range allTypes {
		var (
			servers []*proxytest.Server
			hops    []*Hop
			order   []string
		)
		for i := range allTypes {
			typ := allTypes[(rot+i)%len(allTypes)]
			o := proxytest.Options{Type: typ}
			if i%2 == 1 {
				o.User, o.Pass = "user"+typ, "pass"
			}
			s := start(t, o)
			servers, order = append(servers, s), append(order, typ)
			hops = append(hops, NewHop(s.Config(fmt.Sprintf("hop%d", i))))
		}
		c, err := DialChain(testCtx(t), base, hops, "127.0.0.1", echo.Port())
		if err != nil {
			t.Errorf("%v: %v", order, err)
			continue
		}
		roundTrip(t, c, banner)
		c.Close()
		for i, s := range servers {
			want := target
			if i+1 < len(servers) {
				want = servers[i+1].Addr()
			}
			wantTargets(t, s, want)
		}
	}
}

func TestChainPassesTheNameToTheLastHop(t *testing.T) {
	echo := startEcho(t, "")
	target := fmt.Sprintf("echo.test:%d", echo.Port())
	a := start(t, proxytest.Options{Type: config.TypeHTTPS})
	b := start(t, proxytest.Options{Type: config.TypeSOCKS4A, User: "id"})
	c := start(t, proxytest.Options{Type: config.TypeSOCKS5, User: "u", Pass: "p",
		Dial: proxytest.Mapper(map[string]string{target: echo.Addr()})})
	hops := []*Hop{NewHop(a.Config("a")), NewHop(b.Config("b")), NewHop(c.Config("c"))}
	conn, err := DialChain(testCtx(t), base, hops, "echo.test", echo.Port())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "")
	wantTargets(t, a, b.Addr())
	wantTargets(t, b, c.Addr())
	wantTargets(t, c, target)
}

func TestBrokenChain(t *testing.T) {
	refuse := func(network, addr string) (net.Conn, error) { return nil, errors.New("connection refused") }

	// The first hop cannot reach the second one: that is a broken chain, the
	// destination has nothing to do with it.
	first := start(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: refuse})
	second := config.Proxy{ID: "second", Name: "second", Type: config.TypeHTTP, Host: "192.0.2.1", Port: 8080}
	_, err := DialChain(testCtx(t), base, []*Hop{NewHop(first.Config("first")), NewHop(second)}, "example.test", 80)
	if err == nil || errors.Is(err, ErrTarget) || !strings.Contains(err.Error(), "cannot reach proxy second") {
		t.Errorf("second hop down: %v", err)
	}
	wantTargets(t, first, "192.0.2.1:8080")

	// The last hop cannot reach the destination: this one is about the target.
	first = start(t, proxytest.Options{Type: config.TypeSOCKS5})
	last := start(t, proxytest.Options{Type: config.TypeHTTP, Dial: refuse})
	_, err = DialChain(testCtx(t), base, []*Hop{NewHop(first.Config("first")), NewHop(last.Config("last"))}, "example.test", 80)
	if !errors.Is(err, ErrTarget) || !strings.HasPrefix(err.Error(), "last (http): ") {
		t.Errorf("destination down behind two hops: %v", err)
	}
}

// The deadline that guards the handshake must not stay on the tunnel.
func TestTunnelOutlivesTheHandshakeDeadline(t *testing.T) {
	echo := startEcho(t, "")
	var conns []net.Conn
	for _, typ := range allTypes {
		srv := start(t, proxytest.Options{Type: typ})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := DialChain(ctx, base, []*Hop{NewHop(srv.Config("p"))}, "127.0.0.1", echo.Port())
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		defer c.Close()
		conns = append(conns, c)
	}
	time.Sleep(1200 * time.Millisecond)
	for i, c := range conns {
		buf := make([]byte, 4)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Errorf("%s: write after the handshake deadline: %v", allTypes[i], err)
			continue
		}
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Errorf("%s: read after the handshake deadline: %q, %v", allTypes[i], buf, err)
		}
	}
}

func TestCheck(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer web.Close()
	echo := startEcho(t, "")
	srv := start(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(map[string]string{
		"web.test:80":  strings.TrimPrefix(web.URL, "http://"),
		"echo.test:80": echo.Addr(),
		"echo.test:7":  echo.Addr(),
	})})
	hops := []*Hop{NewHop(srv.Config("p"))}

	if _, err := Check(testCtx(t), base, hops, "web.test:80"); err != nil {
		t.Errorf("web server behind the proxy: %v", err)
	}
	// On port 80 a tunnel that does not answer like a web server is no good.
	if _, err := Check(testCtx(t), base, hops, "echo.test:80"); err == nil || !strings.Contains(err.Error(), "unexpected response") {
		t.Errorf("not a web server on port 80: %v", err)
	}
	// On other ports the open tunnel is all that can be checked.
	if _, err := Check(testCtx(t), base, hops, "echo.test:7"); err != nil {
		t.Errorf("other port: %v", err)
	}
	if _, err := Check(testCtx(t), base, hops, "gone.invalid:80"); !errors.Is(err, ErrTarget) {
		t.Errorf("unknown destination: %v", err)
	}
	for _, bad := range []string{"", "nohost", "host:port", "host:"} {
		if _, err := Check(testCtx(t), base, hops, bad); err == nil {
			t.Errorf("target %q was accepted", bad)
		}
	}
}

func TestHopAccessors(t *testing.T) {
	h := NewHop(config.Proxy{ID: "id", Name: "name", Type: config.TypeHTTPS, Host: "2001:db8::1", Port: 8443})
	if h.ID() != "id" || h.Name() != "name" || h.Type() != config.TypeHTTPS || h.Host() != "2001:db8::1" || h.Port() != 8443 {
		t.Errorf("accessors: %+v", h)
	}
	if h.Addr() != "[2001:db8::1]:8443" {
		t.Errorf("Addr() = %q", h.Addr())
	}
}

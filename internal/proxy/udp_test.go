package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/proxytest"
)

func TestUDPHeaders(t *testing.T) {
	v6 := "\x20\x01\x0d\xb8" + strings.Repeat("\x00", 11) + "\x01"
	cases := []struct {
		host string
		port int
		want string // the header, byte for byte
		back string // what parsing it gives: a name or an address
	}{
		{"192.0.2.7", 53, "\x00\x00\x00\x01\xC0\x00\x02\x07\x00\x35", "192.0.2.7"},
		{"2001:db8::1", 443, "\x00\x00\x00\x04" + v6 + "\x01\xBB", "2001:db8::1"},
		{"::ffff:192.0.2.7", 53, "\x00\x00\x00\x01\xC0\x00\x02\x07\x00\x35", "192.0.2.7"},
		{"fe80::1%eth0", 9, "\x00\x00\x00\x04\xfe\x80" + strings.Repeat("\x00", 13) + "\x01\x00\x09", "fe80::1"},
		{"example.test", 65535, "\x00\x00\x00\x03\x0cexample.test\xFF\xFF", "example.test"},
		{"a", 0, "\x00\x00\x00\x03\x01a\x00\x00", "a"},
	}
	for _, c := range cases {
		got, err := AppendUDPHeader([]byte("pre"), c.host, c.port)
		if err != nil || string(got) != "pre"+c.want {
			t.Errorf("%s:%d: header % x, err %v; want % x", c.host, c.port, got, err, "pre"+c.want)
			continue
		}
		for _, body := range []string{"", "payload"} {
			host, ip, port, payload, err := ParseUDPHeader([]byte(c.want + body))
			if err != nil {
				t.Errorf("%s:%d: parse: %v", c.host, c.port, err)
				continue
			}
			name := host
			if ip.IsValid() {
				name = ip.String()
			}
			if (host != "") == ip.IsValid() || name != c.back || port != c.port || string(payload) != body {
				t.Errorf("%s:%d: parsed as host %q, ip %v, port %d, payload %q", c.host, c.port, host, ip, port, payload)
			}
		}
	}

	long := strings.Repeat("n", 255)
	if b, err := AppendUDPHeader(nil, long, 1); err != nil || len(b) != MaxUDPHeader {
		t.Errorf("the longest name: %d bytes, err %v; want %d", len(b), err, MaxUDPHeader)
	}
	for _, bad := range []struct {
		host string
		port int
		want string
	}{
		{"example.test", -1, "bad port"},
		{"example.test", 65536, "bad port"},
		{"", 53, "bad hostname length"},
		{long + "n", 53, "bad hostname length"},
	} {
		if _, err := AppendUDPHeader(nil, bad.host, bad.port); err == nil || err.Error() != bad.want {
			t.Errorf("%.20q:%d: err %v, want %q", bad.host, bad.port, err, bad.want)
		}
	}

	// The address goes in without its zone and as IPv4 where it is one.
	if got := AppendUDPAddr(nil, netip.MustParseAddrPort("[::ffff:10.1.2.3]:80")); string(got) != "\x00\x00\x00\x01\x0a\x01\x02\x03\x00\x50" {
		t.Errorf("mapped address: % x", got)
	}

	// An IPv4 address in the clothes of IPv6 comes out as IPv4.
	mapped := "\x00\x00\x00\x04" + strings.Repeat("\x00", 10) + "\xff\xff\xC0\x00\x02\x07\x00\x35"
	if _, ip, _, _, err := ParseUDPHeader([]byte(mapped)); err != nil || ip != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("mapped address parsed as %v, err %v", ip, err)
	}
	// The reserved bytes are nobody's business.
	if _, ip, port, _, err := ParseUDPHeader([]byte("\xAA\xBB\x00\x01\x01\x02\x03\x04\x00\x07")); err != nil || ip.String() != "1.2.3.4" || port != 7 {
		t.Errorf("reserved bytes set: %v:%d, err %v", ip, port, err)
	}

	const short = "datagram shorter than its header"
	for _, bad := range []struct{ b, want string }{
		{"", short},
		{"\x00\x00\x00", short},
		{"\x00\x00\x00\x01\x01\x02\x03\x04\x00", short},
		{"\x00\x00\x00\x04" + v6 + "\x01", short},
		{"\x00\x00\x00\x03", short},
		{"\x00\x00\x00\x03\x00\x00\x35", short},
		{"\x00\x00\x00\x03\x05abc\x00\x35", short},
		{"\x00\x00\x01\x01\x01\x02\x03\x04\x00\x35x", "fragmented datagram"},
		{"\x00\x00\x00\x02\x01\x02\x03\x04\x00\x35x", "address type 2"},
	} {
		if _, _, _, _, err := ParseUDPHeader([]byte(bad.b)); err == nil || err.Error() != bad.want {
			t.Errorf("% x: err %v, want %q", bad.b, err, bad.want)
		}
	}
}

// movedConn is a connection that claims to lead somewhere else.
type movedConn struct {
	net.Conn
	remote net.Addr
}

func (m movedConn) RemoteAddr() net.Addr { return m.remote }

func TestAssociateRelayAddress(t *testing.T) {
	const port = "\x0F\xA0" // 4000
	v6 := func(s string) string { a := netip.MustParseAddr(s).As16(); return string(a[:]) }
	far := &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 1080} // sixteen bytes long, as it happens
	cases := []struct {
		name   string
		reply  string // from the address type on
		server net.Addr
		want   string // the relay, or part of the error
	}{
		{"an address", "\x01\x0A\x01\x02\x03" + port, nil, "10.1.2.3:4000"},
		{"every address", "\x01\x00\x00\x00\x00" + port, nil, "127.0.0.1:4000"},
		{"loopback of a local server", "\x01\x7F\x00\x00\x09" + port, nil, "127.0.0.9:4000"},
		{"IPv6", "\x04" + v6("2001:db8::1") + port, nil, "[2001:db8::1]:4000"},
		{"every IPv6 address", "\x04" + v6("::") + port, nil, "127.0.0.1:4000"},
		{"IPv4 as IPv6", "\x04" + v6("::ffff:10.1.2.3") + port, nil, "10.1.2.3:4000"},
		{"loopback of a far server", "\x01\x7F\x00\x00\x01" + port, far, "203.0.113.5:4000"},
		{"every address of a far server", "\x01\x00\x00\x00\x00" + port, far, "203.0.113.5:4000"},
		{"an address of a far server", "\x01\x0A\x01\x02\x03" + port, far, "10.1.2.3:4000"},
		{"a name", "\x03\x0drelay.example" + port, nil, `p (socks5): UDP association: the proxy names its relay "relay.example" instead of giving an address`},
		{"no port", "\x01\x0A\x01\x02\x03\x00\x00", nil, "p (socks5): UDP association: the proxy gave no usable relay address"},
	}
	for _, tc := range cases {
		cfg := canned(t, "\x05\x00\x05\x00\x00"+tc.reply)
		cfg.Type = config.TypeSOCKS5
		hop := NewHop(cfg)
		c, err := base(testCtx(t), "tcp", hop.Addr())
		if err != nil {
			t.Fatal(err)
		}
		var conn net.Conn = c
		if tc.server != nil {
			conn = movedConn{c, tc.server}
		}
		relay, err := hop.Associate(testCtx(t), conn)
		_ = c.Close()
		got := relay.String()
		if err != nil {
			got = err.Error()
			if errors.Is(err, ErrNoUDP) || errors.Is(err, ErrTarget) {
				t.Errorf("%s: %v is marked as a refusal", tc.name, err)
			}
		}
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestAssociateRefusals(t *testing.T) {
	code := func(c byte) string { return "\x05\x00\x05" + string([]byte{c}) + "\x00\x01\x00\x00\x00\x00\x00\x00" }
	const pre = "p (socks5): UDP association: "
	cases := []struct {
		reply string
		noUDP bool
		want  string
	}{
		{code(1), false, pre + "general failure"},
		{code(2), true, "p (socks5): cannot carry UDP: connection not allowed by ruleset"},
		{code(3), false, pre + "network unreachable"},
		{code(4), false, pre + "host unreachable"},
		{code(5), false, pre + "connection refused"},
		{code(6), false, pre + "TTL expired"},
		{code(7), true, "p (socks5): cannot carry UDP: command not supported"},
		{code(8), false, pre + "address type not supported"},
		{code(0x42), false, pre + "reply code 66"},
		{"\x05\xFF", false, pre + "no acceptable authentication method"},
		{"\x05\x02", false, pre + "server requires authentication"},
		{"HTTP/1.1 400 Bad Request\r\n\r\n", false, pre + "not a SOCKS5 server"},
		{"\x05\x00\x05\x00\x00\x09", false, pre + "bad address type in reply"},
	}
	for _, tc := range cases {
		cfg := canned(t, tc.reply)
		cfg.Type = config.TypeSOCKS5
		hop := NewHop(cfg)
		c, err := base(testCtx(t), "tcp", hop.Addr())
		if err != nil {
			t.Fatal(err)
		}
		_, err = hop.Associate(testCtx(t), c)
		_ = c.Close()
		if err == nil || err.Error() != tc.want {
			t.Errorf("%q: err %v, want %s", tc.reply, err, tc.want)
			continue
		}
		if errors.Is(err, ErrNoUDP) != tc.noUDP || errors.Is(err, ErrTarget) {
			t.Errorf("%v: wrongly marked", err)
		}
	}
}

// untouchable is a connection nothing may be done with.
type untouchable struct {
	net.Conn
	t *testing.T
}

func (u untouchable) Read([]byte) (int, error) {
	u.t.Error("read from the connection")
	return 0, io.EOF
}

func (u untouchable) Write(b []byte) (int, error) {
	u.t.Error("wrote to the connection")
	return len(b), nil
}

func (u untouchable) SetDeadline(time.Time) error {
	u.t.Error("set a deadline on the connection")
	return nil
}

func TestOnlySOCKS5CarriesUDP(t *testing.T) {
	for _, typ := range allTypes {
		if typ == config.TypeSOCKS5 {
			continue
		}
		hop := NewHop(config.Proxy{ID: "w", Name: "web", Type: typ, Host: "192.0.2.1", Port: 8080})
		_, err := hop.Associate(testCtx(t), untouchable{t: t})
		if !errors.Is(err, ErrNoUDP) || err.Error() != "web ("+typ+"): cannot carry UDP" {
			t.Errorf("%s: %v", typ, err)
		}
	}
}

func TestSilentProxyDoesNotHoldUpAnAssociation(t *testing.T) {
	cfg := canned(t, "")
	cfg.Type = config.TypeSOCKS5
	hop := NewHop(cfg)
	c, err := base(testCtx(t), "tcp", hop.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, err = hop.Associate(ctx, c)
	if err == nil || errors.Is(err, ErrNoUDP) || !strings.HasPrefix(err.Error(), "p (socks5): UDP association: ") {
		t.Errorf("err %v", err)
	}
	if d := time.Since(begin); d > 5*time.Second {
		t.Errorf("gave up after %v", d)
	}
}

// udpRoundTrip sends msg to host:port through the relay and returns the
// address the reply names and its payload.
func udpRoundTrip(t *testing.T, pc *net.UDPConn, host string, port int, msg string) (string, string) {
	t.Helper()
	dg, err := AppendUDPHeader(nil, host, port)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.Write(append(dg, msg...)); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("no reply through the relay %s: %v", pc.RemoteAddr(), err)
	}
	name, ip, p, payload, err := ParseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("reply % x: %v", buf[:n], err)
	}
	if ip.IsValid() {
		name = ip.String()
	}
	return net.JoinHostPort(name, itoaPort(p)), string(payload)
}

func itoaPort(p int) string {
	return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(p)).String()[len("0.0.0.0:"):]
}

func TestAssociateRelays(t *testing.T) {
	echo, err := proxytest.StartUDPEcho("echo:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(echo.Close)
	dial := proxytest.Mapper(map[string]string{"app.test:53": echo.Addr()})
	cases := []struct {
		name   string
		o      proxytest.Options
		byName string // what a reply from app.test:53 is named
	}{
		{"plain", proxytest.Options{}, echo.Addr()},
		{"with a password", proxytest.Options{User: "u", Pass: "secret"}, echo.Addr()},
		{"relay on every address", proxytest.Options{UDPAnyAddr: true}, echo.Addr()},
		{"replies by name", proxytest.Options{UDPReplyName: true}, "app.test:53"},
	}
	for _, tc := range cases {
		tc.o.Type, tc.o.Dial = config.TypeSOCKS5, dial
		s := start(t, tc.o)
		hop := NewHop(s.Config("p"))
		c, err := base(testCtx(t), "tcp", hop.Addr())
		if err != nil {
			t.Fatal(err)
		}
		// A deadline that is over before the datagrams travel: the association
		// must not inherit it.
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		relay, err := hop.Associate(ctx, c)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !relay.Addr().IsLoopback() || relay.Port() == 0 {
			t.Errorf("%s: relay %s", tc.name, relay)
		}
		time.Sleep(500 * time.Millisecond)
		alive := make(chan error, 1)
		go func() {
			var b [1]byte
			_, err := c.Read(b[:])
			alive <- err
		}()
		select {
		case err := <-alive:
			t.Fatalf("%s: the control connection gave up: %v", tc.name, err)
		case <-time.After(200 * time.Millisecond):
		}

		// One socket for the lot: the relay serves whoever sent first.
		pc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
		if err != nil {
			t.Fatal(err)
		}
		if from, got := udpRoundTrip(t, pc, "127.0.0.1", echo.Port(), "one"); from != echo.Addr() || got != "echo:one" {
			t.Errorf("%s: by address: %q from %s", tc.name, got, from)
		}
		if from, got := udpRoundTrip(t, pc, "app.test", 53, "two"); from != tc.byName || got != "echo:two" {
			t.Errorf("%s: by name: %q from %s, want it from %s", tc.name, got, from, tc.byName)
		}
		if s.Associations() != 1 || s.LiveAssociations() != 1 || len(s.Targets()) != 0 {
			t.Errorf("%s: %d associations, %d live, tunnels %v", tc.name, s.Associations(), s.LiveAssociations(), s.Targets())
		}
		_ = pc.Close()
		_ = c.Close()
		<-alive
		for end := time.Now().Add(10 * time.Second); s.LiveAssociations() != 0; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("%s: the association outlives its connection", tc.name)
			}
		}
	}
}

func TestAssociateAgainstRealRefusals(t *testing.T) {
	ask := func(o proxytest.Options, edit func(*config.Proxy)) error {
		o.Type = config.TypeSOCKS5
		s := start(t, o)
		cfg := s.Config("p")
		if edit != nil {
			edit(&cfg)
		}
		hop := NewHop(cfg)
		c, err := base(testCtx(t), "tcp", hop.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, err = hop.Associate(testCtx(t), c)
		if err == nil {
			t.Fatal("an association was granted")
		}
		if s.Associations() != 0 {
			t.Errorf("%d associations", s.Associations())
		}
		return err
	}
	err := ask(proxytest.Options{NoUDP: true}, nil)
	if !errors.Is(err, ErrNoUDP) || err.Error() != "p (socks5): cannot carry UDP: command not supported" {
		t.Errorf("no UDP: %v", err)
	}
	err = ask(proxytest.Options{User: "u", Pass: "secret"}, func(p *config.Proxy) { p.Password = "wrong" })
	if errors.Is(err, ErrNoUDP) || err.Error() != "p (socks5): UDP association: authentication failed" {
		t.Errorf("wrong password: %v", err)
	}
}

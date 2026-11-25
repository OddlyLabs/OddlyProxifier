package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/procinfo"
	"oddlyproxifier/internal/proxytest"
	"oddlyproxifier/internal/rules"
)

// udpTimers sets the timers of UDP associations for one test. Call it before
// the engine is started: an association copies them when it is made, and the
// engine is stopped before they are put back.
func udpTimers(t *testing.T, idle, retry, refused time.Duration) {
	t.Helper()
	i0, r0, f0 := udpIdle, udpRetry, udpRefused
	t.Cleanup(func() { udpIdle, udpRetry, udpRefused = i0, r0, f0 })
	udpIdle, udpRetry, udpRefused = idle, retry, refused
}

func startUDPEcho(t *testing.T, tag string) *proxytest.UDPEcho {
	t.Helper()
	e, err := proxytest.StartUDPEcho(tag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

// udpClient is a SOCKS5 client that holds a UDP association at the engine.
type udpClient struct {
	t     *testing.T
	ctl   net.Conn       // the association lasts as long as this stays open
	pc    *net.UDPConn   // the client's own socket
	relay netip.AddrPort // where the engine takes the datagrams
}

// askUDP speaks SOCKS5 on c up to the answer to a UDP ASSOCIATE request and
// returns that answer.
func askUDP(t *testing.T, c net.Conn) []byte {
	t.Helper()
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, 2)
	if _, err := io.ReadFull(c, hello); err != nil || !bytes.Equal(hello, []byte{5, 0}) {
		t.Fatalf("greeting answered with % x, err %v", hello, err)
	}
	if _, err := c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("no answer to the request: %v (got % x)", err, reply)
	}
	return reply
}

// associate asks the engine's proxy listener for a UDP association.
func (r *rig) associate() *udpClient {
	r.t.Helper()
	c := r.raw()
	reply := askUDP(r.t, c)
	if !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
		r.t.Fatalf("UDP association answered with % x", reply)
	}
	_ = c.SetDeadline(time.Time{})
	relay := netip.AddrPortFrom(netip.AddrFrom4([4]byte(reply[4:8])), binary.BigEndian.Uint16(reply[8:]))
	if relay.Addr().String() != "127.0.0.1" || relay.Port() == 0 {
		r.t.Fatalf("the engine's relay is at %s", relay)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = pc.Close() })
	return &udpClient{t: r.t, ctl: c, pc: pc, relay: relay}
}

// udpPacket builds a relayed datagram: the header for host:port and the
// payload. An address literal travels as an address unless asName is set.
func udpPacket(host string, port int, payload string, asName bool) []byte {
	b := []byte{0, 0, 0}
	ip, err := netip.ParseAddr(host)
	switch {
	case err != nil || asName:
		b = append(b, 3, byte(len(host)))
		b = append(b, host...)
	case ip.Is4():
		b = append(b, 1)
		b = append(b, ip.AsSlice()...)
	default:
		b = append(b, 4)
		b = append(b, ip.AsSlice()...)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	return append(b, payload...)
}

// parseUDP takes a relayed datagram apart: the address its header names, as
// host:port, and the payload.
func parseUDP(b []byte) (from, payload string, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", "", false
	}
	var host string
	rest := b[4:]
	switch {
	case b[3] == 1 && len(rest) >= 4:
		host, rest = netip.AddrFrom4([4]byte(rest[:4])).String(), rest[4:]
	case b[3] == 4 && len(rest) >= 16:
		host, rest = netip.AddrFrom16([16]byte(rest[:16])).String(), rest[16:]
	case b[3] == 3 && len(rest) >= 1 && len(rest) >= 1+int(rest[0]):
		host, rest = string(rest[1:1+int(rest[0])]), rest[1+int(rest[0]):]
	default:
		return "", "", false
	}
	if len(rest) < 2 {
		return "", "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(rest)))), string(rest[2:]), true
}

func (c *udpClient) sendRaw(b []byte) {
	c.t.Helper()
	if _, err := c.pc.WriteToUDPAddrPort(b, c.relay); err != nil {
		c.t.Fatalf("send: %v", err)
	}
}

func (c *udpClient) send(host string, port int, payload string) {
	c.t.Helper()
	c.sendRaw(udpPacket(host, port, payload, false))
}

// poll waits up to d for a datagram from the engine.
func (c *udpClient) poll(d time.Duration) (from, payload string, ok bool) {
	c.t.Helper()
	deadline := time.Now().Add(d)
	buf := make([]byte, 64<<10)
	for {
		_ = c.pc.SetReadDeadline(deadline)
		n, src, err := c.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() || time.Now().After(deadline) {
				return "", "", false
			}
			// Windows reports here that an earlier datagram bounced.
			time.Sleep(time.Millisecond)
			continue
		}
		if netip.AddrPortFrom(src.Addr().Unmap(), src.Port()) != c.relay {
			c.t.Fatalf("a datagram from %s instead of the relay %s", src, c.relay)
		}
		if from, payload, ok = parseUDP(buf[:n]); !ok {
			c.t.Fatalf("malformed datagram from the engine: % x", buf[:n])
		}
		return from, payload, true
	}
}

func (c *udpClient) recv() (from, payload string) {
	c.t.Helper()
	from, payload, ok := c.poll(10 * time.Second)
	if !ok {
		c.t.Fatal("no datagram came back")
	}
	return from, payload
}

// silent checks that nothing comes back for a while.
func (c *udpClient) silent(d time.Duration) {
	c.t.Helper()
	if from, payload, ok := c.poll(d); ok {
		c.t.Fatalf("unexpected datagram from %s: %q", from, payload)
	}
}

// echo sends msg to host:port, where an echo server with the given tag is
// expected, and returns the address the reply names as its source.
func (c *udpClient) echo(host string, port int, tag, msg string) string {
	c.t.Helper()
	c.send(host, port, msg)
	from, payload := c.recv()
	if payload != tag+msg {
		c.t.Fatalf("%s:%d answered %q, want %q", host, port, payload, tag+msg)
	}
	return from
}

// retry is echo for a destination that is not served yet: it sends until an
// answer arrives and leaves no further answers behind.
func (c *udpClient) retry(host string, port int, tag, msg string) string {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.send(host, port, msg)
		if from, payload, ok := c.poll(50 * time.Millisecond); ok {
			if payload != tag+msg {
				c.t.Fatalf("%s:%d answered %q, want %q", host, port, payload, tag+msg)
			}
			for ok {
				_, _, ok = c.poll(150 * time.Millisecond)
			}
			return from
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("no answer from %s:%d", host, port)
		}
	}
}

// logged counts the log lines that contain sub.
func (r *rig) logged(sub string) int {
	n := 0
	for _, l := range r.e.Logs(0) {
		if strings.Contains(l.Msg, sub) {
			n++
		}
	}
	return n
}

// connecting waits until exactly one connection is live and still being
// opened, and returns it.
func (r *rig) connecting() ConnInfo {
	r.t.Helper()
	var active []ConnInfo
	waitFor(r.t, "one connection being opened", func() bool {
		active, _ = r.e.Connections()
		return len(active) == 1 && active[0].State == StateConnecting
	})
	return active[0]
}

func viaProxy(id string, more ...func(p *config.Profile)) func(p *config.Profile) {
	return func(p *config.Profile) {
		p.Default = config.Action{Type: config.ActionProxy, Target: id}
		for _, m := range more {
			m(p)
		}
	}
}

func portRule(name string, port int, a config.Action) config.Rule {
	return config.Rule{ID: name, Name: name, Enabled: true, Ports: itoa(port), Action: a}
}

func allClosed(t *testing.T, list []ConnInfo) {
	t.Helper()
	for _, ci := range list {
		if ci.State != StateClosed || ci.Error != "" || ci.Network != "udp" {
			t.Errorf("entry %+v, want a UDP one that closed without error", ci)
		}
	}
}

func TestUDPDirect(t *testing.T) {
	a, b := startUDPEcho(t, "a:"), startUDPEcho(t, "b:")
	r := newRig(t, nil)
	c := r.associate()

	if from := c.echo("127.0.0.1", a.Port(), "a:", "one"); from != a.Addr() {
		t.Errorf("reply named %s, want %s", from, a.Addr())
	}
	if from := c.echo("127.0.0.1", b.Port(), "b:", "two!"); from != b.Addr() {
		t.Errorf("reply named %s, want %s", from, b.Addr())
	}
	c.echo("127.0.0.1", a.Port(), "a:", "three")

	live := r.live(2)
	x := live[0]
	if x.Network != "udp" || x.Inbound != "socks5" || x.Action != config.ActionDirect || x.Rule != rules.DefaultRuleName ||
		x.IP != "127.0.0.1" || x.Host != "" || x.Port != a.Port() || x.Via != "" ||
		x.Source != c.ctl.LocalAddr().String() || x.Up != 8 || x.Down != 12 {
		t.Errorf("first flow: %+v", x)
	}
	if y := live[1]; y.Port != b.Port() || y.Up != 4 || y.Down != 6 {
		t.Errorf("second flow: %+v", y)
	}
	// One port towards the world, on loopback for loopback.
	sa, sb := a.Sources(), b.Sources()
	if len(sa) != 1 || !equalStrings(sa, sb) || !strings.HasPrefix(sa[0], "127.0.0.1:") {
		t.Errorf("the echo servers saw %v and %v", sa, sb)
	}
	if st := r.e.Status().Stats; st.Total != 2 || st.Direct != 2 || st.Active != 2 || st.Up != 12 || st.Down != 18 {
		t.Errorf("stats %+v", st)
	}
	if n := r.logged("udp 127.0.0.1:" + itoa(a.Port()) + " open directly (rule: "); n != 1 {
		t.Errorf("%d log lines for the first flow", n)
	}

	// By name: resolved here, and the reply says where it really came from.
	if from := c.echo("localhost", a.Port(), "a:", "four"); from != a.Addr() {
		t.Errorf("reply named %s, want %s", from, a.Addr())
	}
	live = r.live(3)
	if z := live[2]; z.Host != "localhost" || z.IP != "127.0.0.1" || z.Port != a.Port() || z.Action != config.ActionDirect {
		t.Errorf("flow by name: %+v", z)
	}
	// Other spellings of destinations that are known already.
	c.sendRaw(udpPacket("LOCALHOST.", a.Port(), "five", true))
	if _, got := c.recv(); got != "a:five" {
		t.Errorf("got %q", got)
	}
	c.sendRaw(udpPacket("127.0.0.1", b.Port(), "six", true))
	if from, got := c.recv(); got != "b:six" || from != b.Addr() {
		t.Errorf("got %q from %s", got, from)
	}
	r.live(3)

	_ = c.ctl.Close()
	allClosed(t, r.finished(3))
	r.live(0)
}

func TestUDPThroughProxy(t *testing.T) {
	echo, other := startUDPEcho(t, "e:"), startUDPEcho(t, "o:")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(map[string]string{
		"app.test:53": echo.Addr(), "other.test:5353": other.Addr(),
	})})
	r := newRig(t, viaProxy("px", func(p *config.Profile) { p.Proxies = []config.Proxy{px.Config("px")} }))
	c := r.associate()

	// The name goes to the proxy, which answers from the address it reached.
	if from := c.echo("app.test", 53, "e:", "hello"); from != echo.Addr() {
		t.Errorf("reply named %s, want %s", from, echo.Addr())
	}
	x := r.live(1)[0]
	if x.Network != "udp" || x.Host != "app.test" || x.IP != "" || x.Port != 53 || x.Via != "px" ||
		x.Action != config.ActionProxy || x.Rule != rules.DefaultRuleName || x.Up != 5 || x.Down != 7 {
		t.Errorf("flow by name: %+v", x)
	}
	if got := px.UDPTargets(); !equalStrings(got, []string{"app.test:53"}) {
		t.Errorf("the proxy relayed to %v", got)
	}
	c.echo("other.test", 5353, "o:", "hi")
	if n := px.Associations(); n != 2 {
		t.Errorf("%d associations for two names, want one each", n)
	}

	// Addresses share one association.
	if from := c.echo("127.0.0.1", echo.Port(), "e:", "ip1"); from != echo.Addr() {
		t.Errorf("reply named %s", from)
	}
	c.echo("127.0.0.1", other.Port(), "o:", "ip2")
	if n, l := px.Associations(), px.LiveAssociations(); n != 3 || l != 3 {
		t.Errorf("%d associations, %d live; want 3", n, l)
	}
	live := r.live(4)
	if y := live[2]; y.Host != "" || y.IP != "127.0.0.1" || y.Port != echo.Port() || y.Via != "px" {
		t.Errorf("flow by address: %+v", y)
	}
	if len(px.Targets()) != 0 || len(echo.Sources()) != 2 {
		t.Errorf("tunnels %v, sources at the echo %v", px.Targets(), echo.Sources())
	}
	if n := r.logged("udp app.test:53 open through px (rule: "); n != 1 {
		t.Errorf("%d log lines for the first flow", n)
	}

	// The shared association ends with its last flow.
	if !r.e.CloseConn(live[2].ID) {
		t.Fatal("the flow is not listed")
	}
	allClosed(t, r.finished(1))
	c.echo("127.0.0.1", other.Port(), "o:", "ip3")
	if l := px.LiveAssociations(); l != 3 {
		t.Errorf("%d live associations, want 3", l)
	}
	r.e.CloseConn(live[3].ID)
	waitFor(t, "the shared association to end", func() bool { return px.LiveAssociations() == 2 })
	c.echo("127.0.0.1", echo.Port(), "e:", "again")
	if n := px.Associations(); n != 4 {
		t.Errorf("%d associations, want 4", n)
	}
	if st := r.e.Status().Stats; st.Total != 5 || st.Proxied != 5 || st.Failed != 0 {
		t.Errorf("stats %+v", st)
	}

	_ = c.ctl.Close()
	waitFor(t, "the proxy's associations to end", func() bool { return px.LiveAssociations() == 0 })
	allClosed(t, r.finished(5))
}

func TestUDPProxyVariants(t *testing.T) {
	cases := []struct {
		name   string
		o      proxytest.Options
		byName bool // replies name the destination as it was asked for
	}{
		{"relay on every address", proxytest.Options{UDPAnyAddr: true}, false},
		{"replies by name", proxytest.Options{UDPReplyName: true}, true},
		{"with a password", proxytest.Options{User: "u", Pass: "secret"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			echo, moved := startUDPEcho(t, "e:"), startUDPEcho(t, "m:")
			tc.o.Type = config.TypeSOCKS5
			tc.o.Dial = proxytest.Mapper(map[string]string{"app.test:53": echo.Addr(), "10.255.0.1:53": moved.Addr()})
			px := startProxy(t, tc.o)
			r := newRig(t, viaProxy("px", func(p *config.Profile) { p.Proxies = []config.Proxy{px.Config("px")} }))
			c := r.associate()
			want := echo.Addr()
			if tc.byName {
				want = "app.test:53"
			}
			if from := c.echo("app.test", 53, "e:", "name"); from != want {
				t.Errorf("reply named %s, want %s", from, want)
			}
			if from := c.echo("127.0.0.1", echo.Port(), "e:", "addr"); from != echo.Addr() {
				t.Errorf("reply named %s, want %s", from, echo.Addr())
			}
			// An address the proxy reaches somewhere else. Replies are taken
			// from where the client sent to and from nowhere else.
			c.send("10.255.0.1", 53, "moved")
			if tc.byName {
				if from, got := c.recv(); from != "10.255.0.1:53" || got != "m:moved" {
					t.Errorf("got %q from %s", got, from)
				}
			} else {
				waitFor(t, "the datagram to arrive", func() bool { return moved.Received() == 1 })
				c.silent(300 * time.Millisecond)
			}
			r.live(3)
		})
	}
}

func TestUDPBlocked(t *testing.T) {
	udpTimers(t, time.Minute, 200*time.Millisecond, time.Minute)
	echo := startUDPEcho(t, "e:")
	r := newRig(t, func(p *config.Profile) { p.Rules = []config.Rule{blockRule("no", "localhost")} })
	c := r.associate()
	for i := 0; i < 5; i++ {
		c.send("localhost", echo.Port(), "x")
		time.Sleep(60 * time.Millisecond)
	}
	c.silent(300 * time.Millisecond)
	x := r.finished(1)[0]
	if x.State != StateBlocked || x.Rule != "no" || x.Action != config.ActionBlock || x.Network != "udp" || x.Host != "localhost" {
		t.Errorf("entry %+v", x)
	}
	if st := r.e.Status().Stats; echo.Received() != 0 || st.Blocked != 1 || st.Total != 1 {
		t.Errorf("%d datagrams got through, stats %+v", echo.Received(), st)
	}

	// Once the rule is gone the destination is served.
	p := r.e.Profile()
	p.Rules = nil
	if err := r.e.SetProfile(p); err != nil {
		t.Fatal(err)
	}
	c.retry("localhost", echo.Port(), "e:", "now")
	if y := r.live(1)[0]; y.Rule != rules.DefaultRuleName || y.Action != config.ActionDirect {
		t.Errorf("entry %+v", y)
	}
}

func TestUDPNeedsOneSOCKS5Proxy(t *testing.T) {
	e1, e2, e3 := startUDPEcho(t, "1:"), startUDPEcho(t, "2:"), startUDPEcho(t, "3:")
	web := startProxy(t, proxytest.Options{Type: config.TypeHTTP})
	old := startProxy(t, proxytest.Options{Type: config.TypeSOCKS4})
	s1, s2 := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5}), startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{web.Config("web"), old.Config("old"), s1.Config("a"), s2.Config("b")}
		p.Chains = []config.Chain{{ID: "two", Name: "two", Type: config.ChainSimple, Proxies: []string{"a", "b"}}}
		p.Rules = []config.Rule{
			portRule("w", e1.Port(), config.Action{Type: config.ActionProxy, Target: "web"}),
			portRule("o", e2.Port(), config.Action{Type: config.ActionProxy, Target: "old"}),
			portRule("c", e3.Port(), config.Action{Type: config.ActionChain, Target: "two"}),
		}
	})
	c := r.associate()
	for i, tc := range []struct {
		port int
		want string
	}{
		{e1.Port(), "web (http) cannot carry UDP"},
		{e2.Port(), "old (socks4) cannot carry UDP"},
		{e3.Port(), "a → b: a chain of several proxies cannot carry UDP"},
	} {
		for n := 0; n < 3; n++ {
			c.send("127.0.0.1", tc.port, "x")
			time.Sleep(30 * time.Millisecond)
		}
		x := r.finished(i + 1)[i]
		if x.State != StateFailed || x.Error != tc.want || x.Port != tc.port || x.IP != "127.0.0.1" || x.Via != "" {
			t.Errorf("entry %+v, want it failed with %q", x, tc.want)
		}
	}
	c.silent(200 * time.Millisecond)
	if st := r.e.Status().Stats; st.Failed != 3 || st.Total != 3 {
		t.Errorf("stats %+v", st)
	}
	// Nothing went out some other way.
	if n := e1.Received() + e2.Received() + e3.Received() + web.Accepted() + old.Accepted() + s1.Accepted() + s2.Accepted(); n != 0 {
		t.Errorf("%d datagrams or proxy connections", n)
	}
}

func TestUDPSwitchedOff(t *testing.T) {
	echo := startUDPEcho(t, "e:")
	r := newRig(t, func(p *config.Profile) { p.Options.UDP = false })
	refused := func() {
		t.Helper()
		c := r.raw()
		if reply := askUDP(t, c); !bytes.Equal(reply, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}) {
			t.Fatalf("answered with % x", reply)
		}
		expectClosed(t, c)
	}
	refused()
	if n := r.e.Status().Stats.Total; n != 0 {
		t.Errorf("%d connections listed", n)
	}
	set := func(on bool) {
		t.Helper()
		p := r.e.Profile()
		p.Options.UDP = on
		if err := r.e.SetProfile(p); err != nil {
			t.Fatal(err)
		}
	}
	set(true)
	c := r.associate()
	c.echo("127.0.0.1", echo.Port(), "e:", "on")
	r.live(1)

	// Switching it off ends what is being relayed.
	set(false)
	expectClosed(t, c.ctl)
	allClosed(t, r.finished(1))
	refused()
}

func TestUDPEndsWithTheEngine(t *testing.T) {
	echo := startUDPEcho(t, "e:")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(map[string]string{"app.test:53": echo.Addr()})})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Rules = []config.Rule{proxyRule("app", "px", "app.test")}
	})
	c := r.associate()
	c.echo("127.0.0.1", echo.Port(), "e:", "direct")
	c.echo("app.test", 53, "e:", "proxied")
	r.live(2)

	r.e.Stop()
	expectClosed(t, c.ctl)
	allClosed(t, r.finished(2))
	waitFor(t, "the proxy's association to end", func() bool { return px.LiveAssociations() == 0 })

	r.e.Start()
	c = r.associate()
	c.echo("app.test", 53, "e:", "again")
}

func TestUDPFakeDNS(t *testing.T) {
	echo := startUDPEcho(t, "e:")
	port := echo.Port()
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(map[string]string{
		"far.test:" + itoa(port): echo.Addr(),
	})})
	r := newRig(t, fakeDNSProfile(startDNS(t), func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Rules = []config.Rule{proxyRule("far", "px", "far.test")}
	}))
	dns := r.e.fake.Load().Addr().String()
	near, far := resolveA(t, dns, "near.test"), resolveA(t, dns, "far.test")
	c := r.associate()

	// The placeholder stands for the name: it is resolved for real, and the
	// reply comes from the address the client knows.
	want := net.JoinHostPort(near.String(), itoa(port))
	if from := c.echo(near.String(), port, "e:", "n"); from != want {
		t.Errorf("reply named %s, want %s", from, want)
	}
	if x := r.live(1)[0]; x.Host != "near.test" || x.IP != "127.0.0.1" || x.Action != config.ActionDirect || x.Via != "" {
		t.Errorf("direct flow: %+v", x)
	}
	want = net.JoinHostPort(far.String(), itoa(port))
	if from := c.echo(far.String(), port, "e:", "f"); from != want {
		t.Errorf("reply named %s, want %s", from, want)
	}
	if x := r.live(2)[1]; x.Host != "far.test" || x.IP != "" || x.Rule != "far" || x.Via != "px" {
		t.Errorf("proxied flow: %+v", x)
	}
	if got := px.UDPTargets(); !equalStrings(got, []string{"far.test:" + itoa(port)}) {
		t.Errorf("the proxy relayed to %v", got)
	}

	// A placeholder nobody handed out.
	c.send("198.18.200.200", port, "x")
	x := r.finished(1)[0]
	if x.State != StateFailed || x.Error != "unknown fake DNS address (stale DNS cache?)" || x.IP != "198.18.200.200" || x.Host != "" {
		t.Errorf("stale placeholder: %+v", x)
	}
}

func TestUDPNamesResolvedHere(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(p *config.Profile)
		local bool
	}{
		{"DNS mode local", func(p *config.Profile) { p.DNS.Mode = config.DNSLocal }, true},
		{"local names", func(p *config.Profile) { p.DNS.LocalNames = []string{"LocalHost"} }, true},
		{"left to the proxy", func(p *config.Profile) {}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			echo := startUDPEcho(t, "e:")
			port := itoa(echo.Port())
			px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(map[string]string{
				"localhost:" + port: echo.Addr(),
			})})
			r := newRig(t, viaProxy("px", tc.edit, func(p *config.Profile) { p.Proxies = []config.Proxy{px.Config("px")} }))
			c := r.associate()
			if from := c.echo("localhost", echo.Port(), "e:", "x"); from != echo.Addr() {
				t.Errorf("reply named %s, want %s", from, echo.Addr())
			}
			asked, ip := "localhost:"+port, ""
			if tc.local {
				asked, ip = "127.0.0.1:"+port, "127.0.0.1"
			}
			if got := px.UDPTargets(); !equalStrings(got, []string{asked}) {
				t.Errorf("the proxy was asked for %v, want %s", got, asked)
			}
			if x := r.live(1)[0]; x.Host != "localhost" || x.IP != ip || x.Via != "px" {
				t.Errorf("entry %+v", x)
			}
		})
	}
}

func TestUDPIdleFlowsEnd(t *testing.T) {
	udpTimers(t, 500*time.Millisecond, 5*time.Second, time.Minute)
	echo, busy := startUDPEcho(t, "e:"), startUDPEcho(t, "b:")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(map[string]string{"app.test:53": echo.Addr()})})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Rules = []config.Rule{proxyRule("app", "px", "app.test")}
	})
	c := r.associate()
	c.echo("127.0.0.1", echo.Port(), "e:", "d")
	c.echo("app.test", 53, "e:", "p")
	for end := time.Now().Add(1500 * time.Millisecond); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		c.echo("127.0.0.1", busy.Port(), "b:", "k")
	}
	allClosed(t, r.finished(2))
	if x := r.live(1)[0]; x.Port != busy.Port() {
		t.Errorf("the flow left is %+v", x)
	}
	waitFor(t, "the proxy's association to end", func() bool { return px.LiveAssociations() == 0 })

	// The client keeps its port for direct traffic; the proxy is asked anew.
	c.echo("127.0.0.1", echo.Port(), "e:", "again")
	c.echo("app.test", 53, "e:", "again")
	if n := px.Associations(); n != 2 {
		t.Errorf("%d associations, want 2", n)
	}
	seen := echo.Sources() // the engine's own socket, and two of the proxy's
	sort.Strings(seen)
	if len(seen) != 3 || !equalStrings(busy.Sources(), echo.Sources()[:1]) {
		t.Errorf("sources at the echo %v, at the busy one %v", echo.Sources(), busy.Sources())
	}
}

func TestUDPStrangersAreIgnored(t *testing.T) {
	echo := startUDPEcho(t, "e:")
	r := newRig(t, nil)
	c := r.associate()
	knock := func(ip net.IP, to netip.AddrPort, b []byte) bool {
		s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
		if err != nil {
			t.Logf("no socket on %s: %v", ip, err)
			return false
		}
		defer s.Close()
		_, err = s.WriteToUDPAddrPort(b, to)
		return err == nil
	}
	// From another machine, as it were, before the client has said a word.
	knock(net.IPv4(127, 0, 0, 2), c.relay, udpPacket("127.0.0.1", echo.Port(), "stranger", false))
	c.echo("127.0.0.1", echo.Port(), "e:", "mine")
	// From the client's address, but not from its socket.
	knock(net.IPv4(127, 0, 0, 1), c.relay, udpPacket("127.0.0.1", echo.Port(), "theirs", false))
	// What is not a proper datagram, or goes nowhere.
	for _, b := range [][]byte{
		{0, 0, 0},
		{0, 0, 0, 1, 127, 0},
		append([]byte{0, 0, 1}, udpPacket("127.0.0.1", echo.Port(), "fragment", false)[3:]...),
		{0, 0, 0, 2, 127, 0, 0, 1, 0, 53, 'x'},
		{0, 0, 0, 3, 0, 0, 53, 'x'},
		udpPacket("127.0.0.1", 0, "x", false),
		udpPacket(".", 53, "x", true),
	} {
		c.sendRaw(b)
	}
	c.echo("127.0.0.1", echo.Port(), "e:", "mine again")
	if n := echo.Received(); n != 2 {
		t.Errorf("%d datagrams reached the echo, want 2", n)
	}
	// Somebody the client never wrote to sends to the engine's outbound socket.
	out := netip.MustParseAddrPort(echo.Sources()[0])
	if knock(net.IPv4(127, 0, 0, 1), out, []byte("unasked")) {
		c.silent(300 * time.Millisecond)
	}
	r.live(1)
	if st := r.e.Status().Stats; st.Total != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestUDPFailoverGroup(t *testing.T) {
	udpTimers(t, time.Minute, time.Minute, time.Minute)
	e1, e2, e3 := startUDPEcho(t, "1:"), startUDPEcho(t, "2:"), startUDPEcho(t, "3:")
	web := startProxy(t, proxytest.Options{Type: config.TypeHTTP})
	dead := startBroken(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := config.Proxy{ID: "gone", Name: "gone", Type: config.TypeSOCKS5, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
	_ = ln.Close()
	good := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	r := newRig(t, func(p *config.Profile) {
		p.Options.ConnectTimeout = 1
		p.Proxies = []config.Proxy{web.Config("web"), dead.config("dead"), gone, good.Config("good")}
		p.Chains = []config.Chain{
			{ID: "fo", Name: "fo", Type: config.ChainFailover, Proxies: []string{"web", "dead", "gone", "good"}},
			{ID: "bad", Name: "bad", Type: config.ChainFailover, Proxies: []string{"web", "dead"}},
		}
		p.Rules = []config.Rule{portRule("b", e3.Port(), config.Action{Type: config.ActionChain, Target: "bad"})}
		p.Default = config.Action{Type: config.ActionChain, Target: "fo"}
	})
	c := r.associate()
	c.echo("127.0.0.1", e1.Port(), "1:", "x")
	if x := r.live(1)[0]; x.Action != config.ActionChain || x.Via != "good" {
		t.Errorf("entry %+v", x)
	}
	// What was learned is not asked again for the next destination.
	c.echo("127.0.0.1", e2.Port(), "2:", "y")
	r.live(2)
	if dead.hits.Load() != 1 || web.Accepted() != 0 || good.Associations() != 1 {
		t.Errorf("dead was tried %d times, web %d, good has %d associations", dead.hits.Load(), web.Accepted(), good.Associations())
	}
	// Only a proxy that cannot be reached is set back for connections too.
	r.e.failMu.Lock()
	_, goneFailed := r.e.failed["gone"]
	_, deadFailed := r.e.failed["dead"]
	_, deadUDP := r.e.noUDP["dead"]
	r.e.failMu.Unlock()
	if !goneFailed || deadFailed || !deadUDP {
		t.Errorf("gone marked %v, dead marked %v, dead's UDP verdict %v", goneFailed, deadFailed, deadUDP)
	}

	for i := 0; i < 3; i++ {
		c.send("127.0.0.1", e3.Port(), "z")
		time.Sleep(30 * time.Millisecond)
	}
	x := r.finished(1)[0]
	if x.State != StateFailed || !strings.HasPrefix(x.Error, "web (http) cannot carry UDP; dead (socks5): UDP association: ") {
		t.Errorf("entry %+v", x)
	}
	if dead.hits.Load() != 1 || e3.Received() != 0 {
		t.Errorf("dead was tried %d times, %d datagrams got out", dead.hits.Load(), e3.Received())
	}
}

func TestUDPClosingOneFlow(t *testing.T) {
	a, b := startUDPEcho(t, "a:"), startUDPEcho(t, "b:")
	r := newRig(t, nil)
	c := r.associate()
	c.echo("127.0.0.1", a.Port(), "a:", "1")
	c.echo("127.0.0.1", b.Port(), "b:", "2")
	live := r.live(2)
	if !r.e.CloseConn(live[0].ID) {
		t.Fatal("the flow is not listed")
	}
	fin := r.finished(1)
	allClosed(t, fin)
	if fin[0].ID != live[0].ID {
		t.Errorf("closed %+v", fin[0])
	}
	c.echo("127.0.0.1", b.Port(), "b:", "3")
	r.live(1)
	c.echo("127.0.0.1", a.Port(), "a:", "4")
	if now := r.live(2); now[1].ID == live[0].ID || now[1].Port != a.Port() {
		t.Errorf("entries %+v", now)
	}

	r.e.CloseAll()
	allClosed(t, r.finished(3))
	r.live(0)
	// The association itself goes on.
	c.echo("127.0.0.1", a.Port(), "a:", "5")
	r.live(1)
}

func TestUDPProxyThatRefuses(t *testing.T) {
	udpTimers(t, time.Minute, 200*time.Millisecond, time.Minute)
	echo, tcp := startUDPEcho(t, "e:"), startEcho(t, "")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, NoUDP: true})
	r := newRig(t, viaProxy("px", func(p *config.Profile) { p.Proxies = []config.Proxy{px.Config("px")} }))
	c := r.associate()
	const want = "px (socks5): cannot carry UDP: command not supported"
	failed := func(n int) {
		t.Helper()
		x := r.finished(n)[n-1]
		if x.State != StateFailed || x.Error != want || x.Action != config.ActionProxy || x.Via != "" {
			t.Errorf("entry %+v", x)
		}
	}
	// The answer stands for as long as the client keeps trying.
	for i := 0; i < 6; i++ {
		c.send("127.0.0.1", echo.Port(), "x")
		time.Sleep(100 * time.Millisecond)
	}
	failed(1)
	// It holds for every destination, and the proxy is not bothered again.
	c.send("app.test", 53, "y")
	failed(2)
	c.send("127.0.0.1", echo.Port()^1, "z")
	failed(3)
	if n := px.Accepted(); n != 1 {
		t.Errorf("the proxy was asked %d times", n)
	}
	r.e.failMu.Lock()
	_, marked := r.e.failed["px"]
	r.e.failMu.Unlock()
	if marked {
		t.Error("the proxy counts as broken")
	}
	// Connections through it are none the worse.
	roundTrip(t, r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", tcp.Port()), "still here")

	// Saving the profile asks the question again.
	if err := r.e.SetProfile(r.e.Profile()); err != nil {
		t.Fatal(err)
	}
	before := px.Accepted()
	waitFor(t, "the proxy to be asked again", func() bool {
		c.send("127.0.0.1", echo.Port(), "again")
		return px.Accepted() > before
	})
	failed(4)
	time.Sleep(300 * time.Millisecond)
	c.send("127.0.0.1", echo.Port(), "again")
	c.silent(200 * time.Millisecond)
	if n := px.Accepted(); n != before+1 || echo.Received() != 0 {
		t.Errorf("the proxy was asked %d more times, %d datagrams got out", n-before, echo.Received())
	}
	r.finished(4)
}

func TestUDPUpstreamAssociationDies(t *testing.T) {
	const want = "px ended the UDP association"
	setup := func(t *testing.T, retry time.Duration) (*rig, *udpClient, *proxytest.Server, *proxytest.UDPEcho) {
		udpTimers(t, time.Minute, retry, time.Minute)
		echo := startUDPEcho(t, "e:")
		px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
		r := newRig(t, viaProxy("px", func(p *config.Profile) { p.Proxies = []config.Proxy{px.Config("px")} }))
		c := r.associate()
		c.echo("127.0.0.1", echo.Port(), "e:", "1")
		return r, c, px, echo
	}
	t.Run("after a while", func(t *testing.T) {
		r, c, px, echo := setup(t, 100*time.Millisecond)
		time.Sleep(200 * time.Millisecond)
		px.CloseAssociations()
		if x := r.finished(1)[0]; x.State != StateFailed || x.Error != want {
			t.Errorf("entry %+v", x)
		}
		c.echo("127.0.0.1", echo.Port(), "e:", "2")
		r.live(1)
		if n := px.Associations(); n != 2 {
			t.Errorf("%d associations, want 2", n)
		}
	})
	t.Run("at once", func(t *testing.T) {
		r, c, px, echo := setup(t, time.Minute)
		px.CloseAssociations()
		r.finished(1)
		// One that does not last is not asked for again right away.
		for i := 0; i < 3; i++ {
			c.send("127.0.0.1", echo.Port(), "2")
			time.Sleep(30 * time.Millisecond)
		}
		if x := r.finished(2)[1]; x.State != StateFailed || x.Error != want {
			t.Errorf("entry %+v", x)
		}
		if n := px.Associations(); n != 1 {
			t.Errorf("%d associations, want 1", n)
		}
	})
}

func TestUDPGivenUpWhileOpening(t *testing.T) {
	// A proxy that takes the connection and never says a word.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(hits)
				return
			}
			hits <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for c := range hits {
			_ = c.Close()
		}
	})
	mute := config.Proxy{ID: "mute", Name: "mute", Type: config.TypeSOCKS5, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
	r := newRig(t, viaProxy("mute", func(p *config.Profile) { p.Proxies = []config.Proxy{mute} }))
	c := r.associate()
	begin := time.Now()

	c.send("app.test", 53, "x")
	first := r.connecting()
	if !r.e.CloseConn(first.ID) {
		t.Fatal("the flow is not listed")
	}
	fin := r.finished(1)
	allClosed(t, fin)
	if fin[0].ID != first.ID {
		t.Errorf("closed %+v", fin[0])
	}
	// The next datagram starts over.
	c.send("app.test", 53, "y")
	second := r.connecting()
	if second.ID == first.ID {
		t.Error("the entry that was closed is back")
	}
	c.send("127.0.0.1", 9, "z")
	waitFor(t, "two flows being opened", func() bool { a, _ := r.e.Connections(); return len(a) == 2 })

	_ = c.ctl.Close()
	allClosed(t, r.finished(3))
	r.live(0)
	if d := time.Since(begin); d > 8*time.Second {
		t.Errorf("took %v: the flows waited for the proxy", d)
	}
	if st := r.e.Status().Stats; st.Failed != 0 || st.Proxied != 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestUDPOneAddressByNameAndByNumber(t *testing.T) {
	echo := startUDPEcho(t, "e:")
	r := newRig(t, nil)
	c := r.associate()
	c.echo("localhost", echo.Port(), "e:", "by name")
	c.echo("127.0.0.1", echo.Port(), "e:", "by number")
	c.echo("localhost", echo.Port(), "e:", "by name again")
	live := r.live(2)
	if live[0].Host != "localhost" || live[1].Host != "" {
		t.Fatalf("entries %+v", live)
	}
	r.e.CloseConn(live[1].ID)
	r.finished(1)
	// The flow that is left gets the replies.
	c.echo("localhost", echo.Port(), "e:", "alone")
	if x := r.live(1)[0]; x.Host != "localhost" || x.Down <= live[0].Down {
		t.Errorf("entry %+v, before %+v", x, live[0])
	}
}

func TestUDPLocalProxyProgramGoesDirect(t *testing.T) {
	echo := startUDPEcho(t, "e:")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	r := newRig(t, viaProxy("px", func(p *config.Profile) { p.Proxies = []config.Proxy{px.Config("px")} }),
		func(e *Engine) { e.listenerPID = procinfo.ListenerPID })
	c := r.associate()
	c.echo("127.0.0.1", echo.Port(), "e:", "x")
	ci := r.live(1)[0]
	if !ownerKnown(t, ci) {
		return
	}
	if ci.Rule != "(local proxy program)" || ci.Action != config.ActionDirect || ci.Via != "" || px.Accepted() != 0 {
		t.Errorf("entry %+v, %d connections to the proxy", ci, px.Accepted())
	}
}

func TestUDPTooManyDestinations(t *testing.T) {
	r := newRig(t, func(p *config.Profile) { p.Rules = []config.Rule{blockRule("no", "10.0.0.0/8")} })
	c := r.associate()
	total := func() int { return int(r.e.Status().Stats.Total) }
	for port := 1; port <= udpMaxFlows; port++ {
		c.send("10.9.8.7", port, "x")
		if port%64 == 0 {
			waitFor(t, itoa(port)+" destinations", func() bool { return total() == port })
		}
	}
	const warning = "talks UDP to more than 1024 destinations at once"
	if n := r.logged(warning); n != 0 {
		t.Fatalf("warned %d times at the limit", n)
	}
	for port := 2000; port < 2010; port++ {
		c.send("10.9.8.7", port, "x")
	}
	waitFor(t, "the warning", func() bool { return r.logged(warning) > 0 })
	c.send("10.9.8.7", 3000, "x")
	c.silent(200 * time.Millisecond)
	if n, w := total(), r.logged(warning); n != udpMaxFlows || w != 1 {
		t.Errorf("%d entries, %d warnings", n, w)
	}
}

func TestUDPBurstWhileOpening(t *testing.T) {
	echo := startUDPEcho(t, "e:")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(map[string]string{"app.test:53": echo.Addr()})})
	r := newRig(t, viaProxy("px", func(p *config.Profile) { p.Proxies = []config.Proxy{px.Config("px")} }))
	c := r.associate()
	want := []string{"e:m0", "e:m1", "e:m2", "e:m3", "e:m4"}
	for i := range want {
		c.send("app.test", 53, "m"+itoa(i))
	}
	var got []string
	for range want {
		_, payload := c.recv()
		got = append(got, payload)
	}
	sort.Strings(got)
	if !equalStrings(got, want) {
		t.Errorf("got %v", got)
	}
	if x := r.live(1)[0]; x.Up != 10 || x.Down != 20 {
		t.Errorf("entry %+v", x)
	}
	if n := px.Associations(); n != 1 {
		t.Errorf("%d associations", n)
	}
}

func TestUDPIPv6Target(t *testing.T) {
	echo, err := proxytest.StartUDPEchoOn("[::1]:0", "6:")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(echo.Close)
	r := newRig(t, nil)
	c := r.associate()
	if from := c.echo("::1", echo.Port(), "6:", "x"); from != echo.Addr() {
		t.Errorf("reply named %s, want %s", from, echo.Addr())
	}
	if x := r.live(1)[0]; x.IP != "::1" || x.Port != echo.Port() {
		t.Errorf("entry %+v", x)
	}
}

package engine

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/proxytest"
	"oddlyproxifier/internal/rules"
)

func intercepting(edit func(p *config.Profile)) func(p *config.Profile) {
	return func(p *config.Profile) {
		p.Options.Intercept = true
		if edit != nil {
			edit(p)
		}
	}
}

func TestTransparentDirect(t *testing.T) {
	echo := startEcho(t, "")
	r := newRig(t, intercepting(nil))
	c := r.be.dial(t, echo.Addr(), 0)
	roundTrip(t, c, "raw bytes")
	_ = c.Close()
	ci := r.finished(1)[0]
	if ci.Inbound != "transparent" || ci.Action != config.ActionDirect || ci.Rule != rules.DefaultRuleName {
		t.Errorf("%+v", ci)
	}
	if ci.IP != "127.0.0.1" || ci.Port != echo.Port() || ci.State != StateClosed || ci.Up != 9 || ci.Down != 9 {
		t.Errorf("%+v", ci)
	}
}

// The hostname of an intercepted connection is recovered from its first
// bytes and handed to the proxy instead of the address.
func TestTransparentSniffHTTP(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{
		Type: config.TypeSOCKS5,
		Dial: proxytest.Mapper(map[string]string{"web.test:80": echo.Addr()}),
	})
	r := newRig(t, intercepting(func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Rules = []config.Rule{proxyRule("test names", "px", "*.test")}
	}))
	c := r.be.dial(t, "203.0.113.7:80", 0)
	roundTrip(t, c, "GET / HTTP/1.1\r\nHost: web.test\r\n\r\n")
	_ = c.Close()
	if got := px.Targets(); !equalStrings(got, []string{"web.test:80"}) {
		t.Errorf("the proxy was asked for %q", got)
	}
	ci := r.finished(1)[0]
	if ci.Host != "web.test" || ci.IP != "203.0.113.7" || ci.Via != "px" || ci.Rule != "test names" {
		t.Errorf("%+v", ci)
	}
}

func TestTransparentSniffTLS(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{
		Type: config.TypeHTTP,
		Dial: proxytest.Mapper(map[string]string{"secure.test:443": echo.Addr()}),
	})
	r := newRig(t, intercepting(func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Default = config.Action{Type: config.ActionProxy, Target: "px"}
	}))
	c := r.be.dial(t, "203.0.113.8:443", 0)
	go func() {
		// The echo server is no TLS server; only the ClientHello matters.
		_ = tls.Client(c, &tls.Config{ServerName: "secure.test", InsecureSkipVerify: true}).Handshake()
	}()
	waitFor(t, "the proxy request", func() bool { return len(px.Targets()) == 1 })
	if got := px.Targets()[0]; got != "secure.test:443" {
		t.Errorf("the proxy was asked for %q", got)
	}
	_ = c.Close()
	if ci := r.finished(1)[0]; ci.Host != "secure.test" || ci.IP != "203.0.113.8" || ci.Via != "px" {
		t.Errorf("%+v", ci)
	}
}

// The owner reported by the platform decides which application rule applies.
func TestTransparentAppRule(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	r := newRig(t, intercepting(func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		r := proxyRule("me", "px")
		r.Apps = []string{selfName(t)}
		p.Rules = []config.Rule{r}
	}))
	c := r.be.dial(t, echo.Addr(), uint32(os.Getpid()))
	roundTrip(t, c, "mine")
	_ = c.Close()
	ci := r.finished(1)[0]
	if ci.PID != uint32(os.Getpid()) || !strings.EqualFold(ci.App, selfName(t)) {
		t.Errorf("owner: %+v", ci)
	}
	if ci.Rule != "me" || ci.Via != "px" || px.Accepted() != 1 {
		t.Errorf("%+v", ci)
	}
	pol := r.be.lastPolicy(t)
	if len(pol.Apps) != 1 || pol.Apps[0] != strings.ToLower(selfName(t)) {
		t.Errorf("policy applications: %q", pol.Apps)
	}
}

func fakeDNSProfile(upstream string, edit func(p *config.Profile)) func(p *config.Profile) {
	return intercepting(func(p *config.Profile) {
		p.DNS.Fake = config.FakeDNS{Enabled: true, Listen: "127.0.0.1:0", Range: "198.18.0.0/15", Upstream: upstream}
		if edit != nil {
			edit(p)
		}
	})
}

func TestTransparentFakeDNS(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{
		Type: config.TypeSOCKS5,
		Dial: proxytest.Mapper(map[string]string{"mapped.test:8080": echo.Addr()}),
	})
	r := newRig(t, fakeDNSProfile(startDNS(t), func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Rules = []config.Rule{{ID: "d", Name: "stay home", Enabled: true, Hosts: []string{"direct.test"},
			Action: config.Action{Type: config.ActionDirect}}}
		p.Default = config.Action{Type: config.ActionProxy, Target: "px"}
	}))
	st := r.e.Status()
	if !st.FakeDNS.Active || st.FakeDNS.Error != "" || !st.Intercept.Active {
		t.Fatalf("status: %+v", st)
	}
	fake := r.e.fake.Load()
	dns := fake.Addr().String()
	pol := r.be.lastPolicy(t)
	if prefixList(pol.ForceNets) != "198.18.0.0/15" || pol.DNSPort != fake.Addr().(*net.UDPAddr).Port {
		t.Errorf("policy: %+v", pol)
	}

	// A proxied name: the placeholder never leaves the machine.
	ip := resolveA(t, dns, "mapped.test")
	if !fake.Contains(ip) {
		t.Fatalf("mapped.test resolved to %s", ip)
	}
	c := r.be.dial(t, net.JoinHostPort(ip.String(), "8080"), 0)
	roundTrip(t, c, "by name")
	_ = c.Close()
	if got := px.Targets(); !equalStrings(got, []string{"mapped.test:8080"}) {
		t.Errorf("the proxy was asked for %q", got)
	}
	if ci := r.finished(1)[0]; ci.Host != "mapped.test" || ci.IP != "" || ci.Via != "px" {
		t.Errorf("%+v", ci)
	}

	// A direct name: the engine resolves it for real.
	ip = resolveA(t, dns, "direct.test")
	c = r.be.dial(t, net.JoinHostPort(ip.String(), itoa(echo.Port())), 0)
	roundTrip(t, c, "direct")
	_ = c.Close()
	if ci := r.finished(2)[1]; ci.Host != "direct.test" || ci.IP != "127.0.0.1" || ci.Action != config.ActionDirect || ci.Rule != "stay home" {
		t.Errorf("%+v", ci)
	}

	// A placeholder nobody handed out.
	c = r.be.dial(t, "198.18.200.200:80", 0)
	expectClosed(t, c)
	if ci := r.finished(3)[2]; ci.State != StateFailed || ci.Error != "unknown fake DNS address (stale DNS cache?)" {
		t.Errorf("%+v", ci)
	}
}

func TestTransparentStrayAndLoop(t *testing.T) {
	r := newRig(t, intercepting(nil))
	c, err := net.Dial("tcp", r.be.addr(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	expectClosed(t, c)
	if n := r.e.stats.stray.Load(); n != 1 {
		t.Errorf("%d stray connections, want 1", n)
	}

	loop := r.be.dial(t, "127.0.0.1:37080", 0)
	expectClosed(t, loop)
	if st := r.e.Status().Stats; st.Total != 0 {
		t.Errorf("stats: %+v", st)
	}
}

// Where the server speaks first, the engine must not sit waiting for the
// client's first bytes.
func TestTransparentServerFirst(t *testing.T) {
	echo := startEcho(t, "220 ready\r\n")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	oldTimeout := sniffTimeout
	t.Cleanup(func() { sniffTimeout = oldTimeout; delete(serverFirstPorts, echo.Port()) })
	r := newRig(t, intercepting(func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Default = config.Action{Type: config.ActionProxy, Target: "px"}
	}))
	banner := func() time.Duration {
		start := time.Now()
		c := r.be.dial(t, echo.Addr(), 0)
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 11)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "220 ready\r\n" {
			t.Fatalf("banner: %q, %v", buf, err)
		}
		_ = c.Close()
		return time.Since(start)
	}

	sniffTimeout = 100 * time.Millisecond
	if d := banner(); d < 80*time.Millisecond || d > 3*time.Second {
		t.Errorf("unknown port: banner after %v", d)
	}
	r.finished(1)
	sniffTimeout = 5 * time.Second
	serverFirstPorts[echo.Port()] = true
	if d := banner(); d > 2*time.Second {
		t.Errorf("server-first port: banner after %v", d)
	}
}

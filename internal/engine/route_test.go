package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/procinfo"
	"oddlyproxifier/internal/proxytest"
	"oddlyproxifier/internal/rules"
)

// One connection through three proxy servers of three kinds, each of which
// only ever learns about its neighbour.
func TestChain(t *testing.T) {
	echo := startEcho(t, "")
	a := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, User: "alice", Pass: "secret"})
	b := startProxy(t, proxytest.Options{Type: config.TypeHTTP, User: "bob", Pass: "hunter2"})
	c := startProxy(t, proxytest.Options{
		Type: config.TypeHTTPS,
		Dial: proxytest.Mapper(map[string]string{"deep.test:443": echo.Addr()}),
	})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{a.Config("a"), b.Config("b"), c.Config("c")}
		p.Chains = []config.Chain{{ID: "abc", Name: "three hops", Type: config.ChainSimple, Proxies: []string{"a", "b", "c"}}}
		p.Default = config.Action{Type: config.ActionChain, Target: "abc"}
	})

	conn := r.mustTunnel(config.TypeSOCKS5, "deep.test", 443)
	roundTrip(t, conn, "all the way down")
	_ = conn.Close()

	if got, want := a.Targets(), []string{b.Addr()}; !equalStrings(got, want) {
		t.Errorf("first hop was asked for %q, want %q", got, want)
	}
	if got, want := b.Targets(), []string{c.Addr()}; !equalStrings(got, want) {
		t.Errorf("second hop was asked for %q, want %q", got, want)
	}
	if got, want := c.Targets(), []string{"deep.test:443"}; !equalStrings(got, want) {
		t.Errorf("last hop was asked for %q, want %q", got, want)
	}
	ci := r.finished(1)[0]
	if ci.Via != "a → b → c" || ci.Action != config.ActionChain || ci.Rule != rules.DefaultRuleName {
		t.Errorf("%+v", ci)
	}
	if ci.Host != "deep.test" || ci.Port != 443 || ci.State != StateClosed {
		t.Errorf("%+v", ci)
	}
	if ci.Up != int64(len("all the way down")) || ci.Down != ci.Up {
		t.Errorf("%d bytes up, %d down", ci.Up, ci.Down)
	}
	if st := r.e.Status().Stats; st.Proxied != 1 || st.Total != 1 {
		t.Errorf("stats: %+v", st)
	}
}

// A chain is only as good as its weakest hop, and the error has to say which
// one that was.
func TestChainBrokenHop(t *testing.T) {
	a := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	dead := startBroken(t)
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{a.Config("a"), dead.config("dead")}
		p.Chains = []config.Chain{{ID: "ad", Name: "ad", Type: config.ChainSimple, Proxies: []string{"a", "dead"}}}
		p.Default = config.Action{Type: config.ActionChain, Target: "ad"}
	})
	if _, err := r.tunnel(config.TypeSOCKS5, "anything.test", 80); err == nil {
		t.Fatal("a tunnel through a dead hop came up")
	}
	ci := r.finished(1)[0]
	if ci.State != StateFailed || !strings.Contains(ci.Error, "dead") || ci.Via != "" {
		t.Errorf("%+v", ci)
	}
	if dead.hits.Load() != 1 {
		t.Errorf("the dead hop saw %d connections, want 1", dead.hits.Load())
	}
}

func TestFailover(t *testing.T) {
	echo := startEcho(t, "")
	bad := startBroken(t)
	good := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{bad.config("bad"), good.Config("good")}
		p.Chains = []config.Chain{{ID: "fo", Name: "fo", Type: config.ChainFailover, Proxies: []string{"bad", "good"}}}
		p.Default = config.Action{Type: config.ActionChain, Target: "fo"}
	})

	// The first connection finds out that "bad" is down ...
	c := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	roundTrip(t, c, "first")
	_ = c.Close()
	if ci := r.finished(1)[0]; ci.Via != "good" || ci.Action != config.ActionChain || ci.State != StateClosed {
		t.Errorf("first connection: %+v", ci)
	}
	if bad.hits.Load() != 1 {
		t.Fatalf("the broken proxy saw %d connections, want 1", bad.hits.Load())
	}

	// ... and the following ones do not waste time on it.
	for i := 0; i < 3; i++ {
		c = r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
		roundTrip(t, c, "next")
		_ = c.Close()
	}
	r.finished(4)
	if bad.hits.Load() != 1 {
		t.Errorf("the broken proxy was tried again right away: %d connections", bad.hits.Load())
	}
	if good.Accepted() != 4 {
		t.Errorf("the working proxy saw %d connections, want 4", good.Accepted())
	}

	// Once the penalty is over it gets another chance.
	r.e.failMu.Lock()
	r.e.failed["bad"] = time.Now().Add(-2 * failPenalty)
	r.e.failMu.Unlock()
	c = r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	_ = c.Close()
	if bad.hits.Load() != 2 {
		t.Errorf("after the penalty the broken proxy saw %d connections, want 2", bad.hits.Load())
	}
}

func TestFailoverAllBroken(t *testing.T) {
	one, two := startBroken(t), startBroken(t)
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{one.config("one"), two.config("two")}
		p.Chains = []config.Chain{{ID: "fo", Name: "fo", Type: config.ChainFailover, Proxies: []string{"one", "two"}}}
		p.Default = config.Action{Type: config.ActionChain, Target: "fo"}
	})
	for round := int64(1); round <= 2; round++ {
		if _, err := r.tunnel(config.TypeSOCKS5, "anything.test", 80); err == nil {
			t.Fatal("a tunnel through broken proxies came up")
		}
		ci := r.finished(int(round))[round-1]
		if ci.State != StateFailed || !strings.Contains(ci.Error, "one (socks5)") ||
			!strings.Contains(ci.Error, "; two (socks5)") {
			t.Errorf("round %d: %+v", round, ci)
		}
		// With nothing better at hand, penalised proxies are still tried.
		if one.hits.Load() != round || two.hits.Load() != round {
			t.Errorf("round %d: %d and %d connections", round, one.hits.Load(), two.hits.Load())
		}
	}
	if st := r.e.Status().Stats; st.Failed != 2 || st.Proxied != 0 {
		t.Errorf("stats: %+v", st)
	}
}

// A proxy that answers "cannot reach the target" is working fine: trying the
// next one would only repeat the question, and it must not be penalised.
func TestFailoverStopsAtTargetError(t *testing.T) {
	first := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(nil)})
	second := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5, Dial: proxytest.Mapper(nil)})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{first.Config("first"), second.Config("second")}
		p.Chains = []config.Chain{{ID: "fo", Name: "fo", Type: config.ChainFailover, Proxies: []string{"first", "second"}}}
		p.Default = config.Action{Type: config.ActionChain, Target: "fo"}
	})
	if _, err := r.tunnel(config.TypeSOCKS5, "nowhere.test", 80); err == nil {
		t.Fatal("a tunnel to nowhere came up")
	}
	ci := r.finished(1)[0]
	if ci.State != StateFailed || !strings.Contains(ci.Error, "first (socks5)") || strings.Contains(ci.Error, "second") {
		t.Errorf("%+v", ci)
	}
	if first.Accepted() != 1 || second.Accepted() != 0 {
		t.Errorf("%d and %d connections, want 1 and 0", first.Accepted(), second.Accepted())
	}
	r.e.failMu.Lock()
	n := len(r.e.failed)
	r.e.failMu.Unlock()
	if n != 0 {
		t.Errorf("%d proxies are penalised for a target that does not exist", n)
	}
}

func TestBalance(t *testing.T) {
	echo := startEcho(t, "")
	one := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	two := startProxy(t, proxytest.Options{Type: config.TypeHTTP})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{one.Config("one"), two.Config("two")}
		p.Chains = []config.Chain{{ID: "lb", Name: "lb", Type: config.ChainBalance, Proxies: []string{"one", "two"}}}
		p.Default = config.Action{Type: config.ActionChain, Target: "lb"}
	})
	var via []string
	for i := 0; i < 4; i++ {
		c := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
		roundTrip(t, c, "spread")
		_ = c.Close()
		via = append(via, r.finished(i + 1)[i].Via)
	}
	if !equalStrings(via, []string{"one", "two", "one", "two"}) {
		t.Errorf("connections went through %q", via)
	}
	if one.Accepted() != 2 || two.Accepted() != 2 {
		t.Errorf("%d and %d connections, want 2 and 2", one.Accepted(), two.Accepted())
	}

	// With one member gone, the other one takes everything.
	two.Close()
	for i := 0; i < 3; i++ {
		c := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
		roundTrip(t, c, "spread")
		_ = c.Close()
		if ci := r.finished(5 + i)[4+i]; ci.Via != "one" {
			t.Errorf("connection %d after the outage went through %q", i+1, ci.Via)
		}
	}
}

// An application that has been configured to use the proxy server itself
// must reach it directly: sending that connection through the same server
// once more would double every hop.
func TestProxyServerIsReachedDirectly(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost"} {
		t.Run(host, func(t *testing.T) {
			echo := startEcho(t, "")
			px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
			cfg := px.Config("px")
			cfg.Host = host
			r := newRig(t, func(p *config.Profile) {
				p.Proxies = []config.Proxy{cfg}
				p.Default = config.Action{Type: config.ActionProxy, Target: "px"}
			})

			c, err := r.viaEngine("127.0.0.1", echo.Port(), px.Config("px"))
			if err != nil {
				t.Fatal(err)
			}
			roundTrip(t, c, "once is enough")
			_ = c.Close()

			ci := r.finished(1)[0]
			if ci.Rule != "(proxy server)" || ci.Action != config.ActionDirect || ci.Via != "" || ci.Port != px.Port() {
				t.Errorf("%+v", ci)
			}
			if px.Accepted() != 1 || !equalStrings(px.Targets(), []string{echo.Addr()}) {
				t.Errorf("the proxy saw %d connection(s) asking for %q", px.Accepted(), px.Targets())
			}

			// Everything else still goes through it.
			c = r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
			roundTrip(t, c, "proxied")
			_ = c.Close()
			if ci := r.finished(2)[1]; ci.Via != "px" || ci.Rule != rules.DefaultRuleName {
				t.Errorf("%+v", ci)
			}
		})
	}
}

// A block rule wins over the exemption for proxy servers.
func TestProxyServerCanBeBlocked(t *testing.T) {
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Rules = []config.Rule{blockRule("nobody", "127.0.0.1")}
		p.Default = config.Action{Type: config.ActionProxy, Target: "px"}
	})
	if _, err := r.tunnel(config.TypeSOCKS5, "127.0.0.1", px.Port()); err == nil {
		t.Fatal("a blocked connection came up")
	}
	if ci := r.finished(1)[0]; ci.State != StateBlocked || ci.Rule != "nobody" {
		t.Errorf("%+v", ci)
	}
	if px.Accepted() != 0 {
		t.Error("a blocked connection reached the proxy")
	}
}

// The connections of a proxy program running on this machine must not be
// sent back into that same program. Here the test process is both: it runs
// the proxy server and it opens the connection.
func TestLocalProxyProgramGoesDirect(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Default = config.Action{Type: config.ActionProxy, Target: "px"}
	}, func(e *Engine) { e.listenerPID = procinfo.ListenerPID })

	c := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	roundTrip(t, c, "not through myself")
	_ = c.Close()
	ci := r.finished(1)[0]
	if !ownerKnown(t, ci) {
		return
	}
	if ci.Rule != "(local proxy program)" || ci.Action != config.ActionDirect || ci.Via != "" {
		t.Errorf("%+v", ci)
	}
	if px.Accepted() != 0 {
		t.Errorf("the connection was fed back into the proxy program (%d connections)", px.Accepted())
	}
}

func TestCheck(t *testing.T) {
	echo := startEcho(t, "")
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(web.Close)
	dial := proxytest.Mapper(map[string]string{
		"check.test:80": web.Listener.Addr().String(),
		"echo.test:80":  echo.Addr(),
	})
	one := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	two := startProxy(t, proxytest.Options{Type: config.TypeHTTP, User: "u", Pass: "p", Dial: dial})
	dead := startBroken(t)
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{one.Config("one"), two.Config("two"), dead.config("dead")}
		p.Chains = []config.Chain{
			{ID: "both", Name: "one then two", Type: config.ChainSimple, Proxies: []string{"one", "two"}},
			{ID: "either", Name: "either", Type: config.ChainFailover, Proxies: []string{"one", "two"}},
		}
	})
	ctx := context.Background()

	for _, tc := range []struct {
		kind, id, target string
		via, err         string // err "" = must succeed
	}{
		{"proxy", "one", echo.Addr(), "one", ""},
		{"proxy", "two", "check.test:80", "two", ""},
		{"chain", "both", "check.test:80", "one then two", ""},
		{"proxy", "two", "echo.test:80", "two", "unexpected response through tunnel"},
		{"proxy", "two", "missing.test:80", "two", "CONNECT refused: 502 Bad Gateway"},
		{"proxy", "dead", echo.Addr(), "dead", "dead (socks5)"},
		{"proxy", "nope", echo.Addr(), "", "unknown proxy"},
		{"chain", "nope", echo.Addr(), "", "unknown chain"},
		{"chain", "either", echo.Addr(), "", "only simple chains can be checked as a whole"},
		{"rule", "one", echo.Addr(), "", "unknown kind"},
		{"proxy", "one", "no-port.test", "one", "target must be host:port"},
	} {
		res := r.e.Check(ctx, tc.kind, tc.id, tc.target)
		if res.Target != tc.target || res.Via != tc.via {
			t.Errorf("%s %s -> %s: result %+v", tc.kind, tc.id, tc.target, res)
		}
		if tc.err == "" {
			if !res.OK || res.Error != "" || res.Millis < 0 {
				t.Errorf("%s %s -> %s: %+v", tc.kind, tc.id, tc.target, res)
			}
		} else if res.OK || !strings.Contains(res.Error, tc.err) {
			t.Errorf("%s %s -> %s: %+v, want error %q", tc.kind, tc.id, tc.target, res, tc.err)
		}
	}

	// A proxy that is not part of the profile yet.
	tmp := two.Config("tmp")
	tmp.Name = "not saved yet"
	if res := r.e.CheckProxy(ctx, tmp, "check.test:80"); !res.OK || res.Via != "not saved yet" {
		t.Errorf("unsaved proxy: %+v", res)
	}
	tmp.Password = "wrong"
	if res := r.e.CheckProxy(ctx, tmp, "check.test:80"); res.OK || !strings.Contains(res.Error, "proxy authentication required") {
		t.Errorf("unsaved proxy with a wrong password: %+v", res)
	}

	// Checks are not connections of any application.
	if st := r.e.Status().Stats; st.Total != 0 {
		t.Errorf("checks show up as connections: %+v", st)
	}
}

// A check must not hang on a proxy that accepts and then says nothing.
func TestCheckTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() }) // keep it open and silent
		}
	}()
	r := newRig(t, func(p *config.Profile) {
		p.Options.ConnectTimeout = 1
		p.Proxies = []config.Proxy{{
			ID: "mute", Name: "mute", Type: config.TypeSOCKS5, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		}}
	})
	start := time.Now()
	res := r.e.Check(context.Background(), "proxy", "mute", "example.test:443")
	if res.OK || res.Error == "" {
		t.Errorf("%+v", res)
	}
	if d := time.Since(start); d < 500*time.Millisecond || d > 5*time.Second {
		t.Errorf("the check took %v with a connect timeout of 1s", d)
	}
}

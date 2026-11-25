package engine

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/proxy"
	"oddlyproxifier/internal/proxytest"
	"oddlyproxifier/internal/rules"
)

// The four ways a client can ask the proxy listener for a tunnel.
var inboundTypes = []struct {
	typ     string // protocol the client speaks
	inbound string // how the engine labels the connection
}{
	{config.TypeSOCKS5, "socks5"},
	{config.TypeSOCKS4, "socks4"},
	{config.TypeSOCKS4A, "socks4"},
	{config.TypeHTTP, "http"},
}

func TestInboundDirect(t *testing.T) {
	echo := startEcho(t, "")
	r := newRig(t, nil)
	const msg = "hello through the engine"

	for i, in := range inboundTypes {
		c := r.mustTunnel(in.typ, "127.0.0.1", echo.Port())
		roundTrip(t, c, msg)
		if got := r.live(1)[0]; got.State != StateOpen || got.Inbound != in.inbound {
			t.Errorf("%s: live connection %+v", in.typ, got)
		}
		_ = c.Close()

		ci := r.finished(i + 1)[i]
		if ci.ID != uint64(i+1) || ci.Inbound != in.inbound || ci.State != StateClosed || ci.Error != "" {
			t.Errorf("%s: %+v", in.typ, ci)
		}
		if ci.Rule != rules.DefaultRuleName || ci.Action != config.ActionDirect || ci.Via != "" {
			t.Errorf("%s: rule %q, action %q, via %q", in.typ, ci.Rule, ci.Action, ci.Via)
		}
		if ci.Host != "" || ci.IP != "127.0.0.1" || ci.Port != echo.Port() {
			t.Errorf("%s: target host %q, IP %q, port %d", in.typ, ci.Host, ci.IP, ci.Port)
		}
		if ci.Up != int64(len(msg)) || ci.Down != int64(len(msg)) {
			t.Errorf("%s: %d bytes up, %d down, want %d each", in.typ, ci.Up, ci.Down, len(msg))
		}
		if !strings.HasPrefix(ci.Source, "127.0.0.1:") || ci.Start == 0 || ci.End < ci.Start {
			t.Errorf("%s: source %q, start %d, end %d", in.typ, ci.Source, ci.Start, ci.End)
		}
		if ownerKnown(t, ci) {
			if ci.PID != uint32(os.Getpid()) || !strings.EqualFold(ci.App, selfName(t)) || ci.AppPath == "" {
				t.Errorf("%s: owner PID %d, %q (%q); this is PID %d, %q",
					in.typ, ci.PID, ci.App, ci.AppPath, os.Getpid(), selfName(t))
			}
		}
	}

	n := int64(len(inboundTypes))
	st := r.e.Status().Stats
	if st.Total != n || st.Direct != n || st.Active != 0 || st.Proxied+st.Blocked+st.Failed != 0 {
		t.Errorf("stats: %+v", st)
	}
	if st.Up != n*int64(len(msg)) || st.Down != n*int64(len(msg)) {
		t.Errorf("byte counters: %+v", st)
	}
	if echo.Accepted() != len(inboundTypes) {
		t.Errorf("the server saw %d connections, want %d", echo.Accepted(), len(inboundTypes))
	}
}

// A hostname given to the proxy listener must reach the proxy server as a
// name: resolving it is the proxy's business.
func TestInboundNameGoesToProxy(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{
		Type: config.TypeSOCKS5,
		Dial: proxytest.Mapper(map[string]string{"app.test:80": echo.Addr()}),
	})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Rules = []config.Rule{proxyRule("test names", "px", "*.test")}
	})

	// Plain SOCKS4 has no way to carry a name.
	types := []string{config.TypeSOCKS5, config.TypeSOCKS4A, config.TypeHTTP}
	for i, typ := range types {
		c := r.mustTunnel(typ, "App.Test", 80)
		roundTrip(t, c, "ping")
		_ = c.Close()
		ci := r.finished(i + 1)[i]
		if ci.Host != "app.test" || ci.IP != "" || ci.Port != 80 {
			t.Errorf("%s: target host %q, IP %q, port %d", typ, ci.Host, ci.IP, ci.Port)
		}
		if ci.Rule != "test names" || ci.Action != config.ActionProxy || ci.Via != "px" || ci.State != StateClosed {
			t.Errorf("%s: %+v", typ, ci)
		}
	}
	if got := px.Targets(); !equalStrings(got, []string{"app.test:80", "app.test:80", "app.test:80"}) {
		t.Errorf("the proxy was asked for %q", got)
	}
	if st := r.e.Status().Stats; st.Proxied != 3 || st.Direct != 0 || st.Total != 3 {
		t.Errorf("stats: %+v", st)
	}

	// A name nobody can resolve fails at the proxy, not here.
	_, err := r.tunnel(config.TypeSOCKS5, "missing.test", 80)
	if err == nil || !errors.Is(err, proxy.ErrTarget) {
		t.Fatalf("tunnel to an unknown name: %v", err)
	}
	ci := r.finished(4)[3]
	if ci.State != StateFailed || !strings.Contains(ci.Error, "host unreachable") || ci.Host != "missing.test" {
		t.Errorf("unknown name: %+v", ci)
	}
}

func TestDNSMode(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		asked  string // what the proxy is asked for
		wantIP string
	}{
		{config.DNSAuto, "localhost", ""},
		{config.DNSRemote, "localhost", ""},
		{config.DNSLocal, "127.0.0.1", "127.0.0.1"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			echo := startEcho(t, "")
			px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
			r := newRig(t, func(p *config.Profile) {
				p.DNS.Mode = tc.mode
				p.Proxies = []config.Proxy{px.Config("px")}
				p.Rules = []config.Rule{proxyRule("by name", "px", "localhost")}
			})
			c := r.mustTunnel(config.TypeSOCKS5, "localhost", echo.Port())
			roundTrip(t, c, "ping")
			_ = c.Close()

			want := net.JoinHostPort(tc.asked, itoa(echo.Port()))
			if got := px.Targets(); !equalStrings(got, []string{want}) {
				t.Errorf("the proxy was asked for %q, want %q", got, want)
			}
			ci := r.finished(1)[0]
			if ci.Host != "localhost" || ci.IP != tc.wantIP || ci.Via != "px" || ci.Rule != "by name" {
				t.Errorf("%+v", ci)
			}
		})
	}
}

func TestInboundBlockAndFailure(t *testing.T) {
	bad := refuser(t)
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{bad.Config("bad")}
		p.Rules = []config.Rule{
			blockRule("no entry", "203.0.113.9"),
			proxyRule("dead end", "bad", "203.0.113.10"),
		}
	})
	cases := []struct {
		typ, blocked, failed string
	}{
		{config.TypeSOCKS5, "connection not allowed by ruleset", "connection refused"},
		{config.TypeSOCKS4, "request rejected or failed", "request rejected or failed"},
		{config.TypeSOCKS4A, "request rejected or failed", "request rejected or failed"},
		{config.TypeHTTP, "CONNECT refused: 403 Forbidden", "CONNECT refused: 502 Bad Gateway"},
	}
	for i, tc := range cases {
		_, err := r.tunnel(tc.typ, "203.0.113.9", 80)
		if err == nil || !strings.Contains(err.Error(), tc.blocked) || !errors.Is(err, proxy.ErrTarget) {
			t.Errorf("%s, blocked target: %v", tc.typ, err)
		}
		ci := r.finished(2*i + 1)[2*i]
		if ci.State != StateBlocked || ci.Action != config.ActionBlock || ci.Rule != "no entry" || ci.Error != "" {
			t.Errorf("%s, blocked target: %+v", tc.typ, ci)
		}
		if ci.IP != "203.0.113.9" || ci.Port != 80 || ci.End == 0 {
			t.Errorf("%s, blocked target: %+v", tc.typ, ci)
		}

		_, err = r.tunnel(tc.typ, "203.0.113.10", 80)
		if err == nil || !strings.Contains(err.Error(), tc.failed) || !errors.Is(err, proxy.ErrTarget) {
			t.Errorf("%s, unreachable target: %v", tc.typ, err)
		}
		ci = r.finished(2*i + 2)[2*i+1]
		if ci.State != StateFailed || ci.Action != config.ActionProxy || ci.Rule != "dead end" {
			t.Errorf("%s, unreachable target: %+v", tc.typ, ci)
		}
		if !strings.Contains(ci.Error, "bad (socks5)") || !strings.Contains(ci.Error, "connection refused") {
			t.Errorf("%s, unreachable target: error %q", tc.typ, ci.Error)
		}
	}
	n := int64(len(cases))
	st := r.e.Status().Stats
	if st.Total != 2*n || st.Blocked != n || st.Failed != n || st.Proxied != 0 || st.Direct != 0 || st.Active != 0 {
		t.Errorf("stats: %+v", st)
	}
	if got := bad.Accepted(); got != len(cases) {
		t.Errorf("the proxy saw %d connections, want %d: a blocked target must not reach it", got, len(cases))
	}
}

func TestInboundDirectFailure(t *testing.T) {
	// A port nobody listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	r := newRig(t, nil)
	_, err = r.tunnel(config.TypeSOCKS5, "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("tunnel to a closed port: %v", err)
	}
	ci := r.finished(1)[0]
	if ci.State != StateFailed || ci.Action != config.ActionDirect || ci.Error == "" || ci.Port != port {
		t.Errorf("%+v", ci)
	}
	if st := r.e.Status().Stats; st.Failed != 1 || st.Direct != 0 || st.Total != 1 {
		t.Errorf("stats: %+v", st)
	}
}

// Rules by application also apply to clients of the proxy listener when they
// run on this machine.
func TestInboundAppRule(t *testing.T) {
	echo := startEcho(t, "")
	r := newRig(t, func(p *config.Profile) {
		p.Rules = []config.Rule{{
			ID: "me", Name: "this test", Enabled: true, Apps: []string{strings.ToUpper(selfName(t))},
			Action: config.Action{Type: config.ActionBlock},
		}}
	})
	_, err := r.tunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	ci := r.finished(1)[0]
	if !ownerKnown(t, ci) {
		return
	}
	if err == nil || !strings.Contains(err.Error(), "connection not allowed by ruleset") {
		t.Errorf("tunnel: %v", err)
	}
	if ci.State != StateBlocked || ci.Rule != "this test" {
		t.Errorf("%+v", ci)
	}
	if echo.Accepted() != 0 {
		t.Error("a blocked connection reached the server")
	}
}

// What the proxy listener cannot do, it has to refuse in the protocol's own
// terms instead of just hanging up.
func TestSocksRefusals(t *testing.T) {
	r := newRig(t, nil)
	type step struct{ send, want []byte }
	hello := step{[]byte{5, 1, 0}, []byte{5, 0}}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"SOCKS5 client that insists on a password", []step{
			{[]byte{5, 1, 2}, []byte{5, 0xFF}},
		}},
		{"SOCKS5 BIND", []step{
			hello, {[]byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80}, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}},
		}},
		{"SOCKS5 BIND to a name", []step{
			hello, {[]byte{5, 2, 0, 3, 4, 'h', 'o', 's', 't', 0, 80}, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}},
		}},
		{"SOCKS5 unknown address type", []step{
			hello, {[]byte{5, 1, 0, 5}, []byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}},
		}},
		{"SOCKS4 BIND", []step{
			{[]byte{4, 2, 0, 80, 127, 0, 0, 1, 'm', 'e', 0}, []byte{0, 0x5B, 0, 0, 0, 0, 0, 0}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := r.raw()
			for _, s := range tc.steps {
				if _, err := c.Write(s.send); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(s.want))
				if _, err := io.ReadFull(c, got); err != nil {
					t.Fatalf("after % x: %v", s.send, err)
				}
				if !bytes.Equal(got, s.want) {
					t.Fatalf("after % x: got % x, want % x", s.send, got, s.want)
				}
			}
			expectClosed(t, c)
		})
	}
	if st := r.e.Status().Stats; st.Total != 0 {
		t.Errorf("refused requests show up as connections: %+v", st)
	}
}

func TestInboundIPv6Target(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	r := newRig(t, nil)
	for i, typ := range []string{config.TypeSOCKS5, config.TypeHTTP} {
		c := r.mustTunnel(typ, "::1", port)
		roundTrip(t, c, "six")
		_ = c.Close()
		ci := r.finished(i + 1)[i]
		if ci.IP != "::1" || ci.Host != "" || ci.Port != port || ci.State != StateClosed {
			t.Errorf("%s: %+v", typ, ci)
		}
	}
}

// Whatever the client sends right behind its request belongs to the tunnel.
func TestInboundEarlyData(t *testing.T) {
	echo := startEcho(t, "")
	r := newRig(t, nil)
	addr := echo.Addr()

	c := r.raw()
	if _, err := io.WriteString(c, "CONNECT "+addr+" HTTP/1.1\r\nHost: "+addr+"\r\n\r\nearly bird"); err != nil {
		t.Fatal(err)
	}
	const established = "HTTP/1.1 200 Connection established\r\n\r\n"
	got := make([]byte, len(established)+len("early bird"))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("%v (got %q)", err, got)
	}
	if string(got) != established+"early bird" {
		t.Errorf("got %q", got)
	}

	// SOCKS5: greeting, request and payload in a single write.
	c = r.raw()
	req := []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, byte(echo.Port() >> 8), byte(echo.Port())}
	if _, err := c.Write(append(req, "early bird"...)); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0}, "early bird"...)
	got = make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("%v (got % x)", err, got)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got % x, want % x", got, want)
	}
}

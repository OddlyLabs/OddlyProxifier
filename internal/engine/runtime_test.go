package engine

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/proxytest"
)

func TestConnectionsAndClose(t *testing.T) {
	echo := startEcho(t, "")
	r := newRig(t, nil)
	a := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	b := r.mustTunnel(config.TypeHTTP, "127.0.0.1", echo.Port())
	roundTrip(t, a, "a")
	roundTrip(t, b, "b")
	live := r.live(2)
	if live[0].ID != 1 || live[1].ID != 2 || live[0].Up != 1 {
		t.Errorf("live connections: %+v", live)
	}
	if r.e.CloseConn(999) {
		t.Error("closing an unknown connection succeeded")
	}
	if !r.e.CloseConn(1) {
		t.Fatal("closing connection 1 failed")
	}
	expectClosed(t, a)
	r.finished(1)
	roundTrip(t, b, "still here")
	r.e.CloseAll()
	expectClosed(t, b)
	r.finished(2)
	if st := r.e.Status().Stats; st.Active != 0 || st.Total != 2 {
		t.Errorf("stats: %+v", st)
	}
}

func TestSetProfileLive(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{Type: config.TypeSOCKS5})
	r := newRig(t, nil)
	port := r.port()
	old := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	roundTrip(t, old, "before")

	p := r.e.Profile()
	p.Proxies = []config.Proxy{px.Config("px")}
	p.Default = config.Action{Type: config.ActionProxy, Target: "px"}
	if err := r.e.SetProfile(p); err != nil {
		t.Fatal(err)
	}
	if r.port() != port {
		t.Errorf("the proxy listener moved from port %d to %d", port, r.port())
	}
	roundTrip(t, old, "after") // open connections keep their route
	c := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	roundTrip(t, c, "new")
	_ = c.Close()
	if ci := r.finished(1)[0]; ci.Via != "px" {
		t.Errorf("new connection: %+v", ci)
	}

	p = r.e.Profile()
	p.Default = config.Action{Type: config.ActionProxy, Target: "nope"}
	err := r.e.SetProfile(p)
	if err == nil || !strings.Contains(err.Error(), `default rule: unknown proxy "nope"`) {
		t.Errorf("invalid profile: %v", err)
	}
	if got := r.e.Profile().Default.Target; got != "px" {
		t.Errorf("an invalid profile replaced the active one (default target %q)", got)
	}
}

func TestInterceptionLifecycle(t *testing.T) {
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{{ID: "px", Name: "px", Type: config.TypeSOCKS5, Host: "192.0.2.1", Port: 1080}}
	})
	set := func(edit func(p *config.Profile)) Status {
		t.Helper()
		p := r.e.Profile()
		edit(p)
		if err := r.e.SetProfile(p); err != nil {
			t.Fatal(err)
		}
		return r.e.Status()
	}
	if st := r.e.Status(); st.Intercept.Enabled || st.Intercept.Active {
		t.Fatalf("interception without being asked: %+v", st.Intercept)
	}
	if _, _, resets := r.be.listens, 0, r.be.resets; resets != 1 {
		t.Errorf("leftovers of an earlier run were cleaned %d times, want once", resets)
	}

	// Switched on, but no rule needs it.
	st := set(func(p *config.Profile) { p.Options.Intercept = true })
	if st.Intercept.Active || st.Intercept.Detail != "idle: no rule sends traffic to a proxy" || st.Intercept.Error != "" {
		t.Errorf("idle: %+v", st.Intercept)
	}
	if l, a, _ := r.be.counts(); l != 1 || a != 0 {
		t.Errorf("idle: %d listens, %d policies", l, a)
	}

	st = set(func(p *config.Profile) { p.Default = config.Action{Type: config.ActionProxy, Target: "px"} })
	if !st.Intercept.Active || st.Intercept.Detail != "" {
		t.Errorf("active: %+v", st.Intercept)
	}
	if l, a, s := r.be.counts(); l != 1 || a != 1 || s != 0 {
		t.Errorf("active: %d listens, %d policies, %d stops", l, a, s)
	}

	st = set(func(p *config.Profile) { p.Default = config.Action{Type: config.ActionDirect} })
	if _, _, s := r.be.counts(); st.Intercept.Active || s != 1 {
		t.Errorf("back to idle: %+v, %d stops", st.Intercept, s)
	}

	// A backend that cannot apply the policy.
	r.be.fail(errors.New("driver says no"), nil)
	st = set(func(p *config.Profile) { p.Default = config.Action{Type: config.ActionBlock} })
	if st.Intercept.Active || st.Intercept.Error != "driver says no" {
		t.Errorf("apply error: %+v", st.Intercept)
	}
	// Saving again after the cause is gone is enough.
	r.be.fail(nil, nil)
	if st = set(func(p *config.Profile) {}); !st.Intercept.Active || st.Intercept.Error != "" {
		t.Errorf("after the retry: %+v", st.Intercept)
	}

	st = set(func(p *config.Profile) { p.Options.Intercept = false })
	if _, _, s := r.be.counts(); st.Intercept.Active || st.Intercept.Enabled || s != 2 {
		t.Errorf("switched off: %+v, %d stops", st.Intercept, s)
	}

	// A listener that cannot be opened, and the retry.
	r.be.fail(nil, errors.New("port taken"))
	st = set(func(p *config.Profile) { p.Options.Intercept = true })
	if st.Intercept.Active || st.Intercept.Error != "port taken" {
		t.Errorf("listen error: %+v", st.Intercept)
	}
	r.be.fail(nil, nil)
	if st = set(func(p *config.Profile) {}); !st.Intercept.Active || st.Intercept.Error != "" {
		t.Errorf("after the listen retry: %+v", st.Intercept)
	}

	r.e.Stop()
	if _, _, s := r.be.counts(); s != 3 {
		t.Errorf("%d stops after shutdown, want 3", s)
	}
}

func TestStatus(t *testing.T) {
	r := newRig(t, nil)
	st := r.e.Status()
	if st.Version != Version || st.OS != runtime.GOOS || st.Arch != runtime.GOARCH || st.PID == 0 || st.Backend != "fake" {
		t.Errorf("%+v", st)
	}
	if !st.Inbound.Enabled || !st.Inbound.Active || st.Inbound.Detail != "127.0.0.1:0" || st.FakeDNS.Enabled {
		t.Errorf("%+v", st)
	}
	if st.BackendInfo["fake"] != true {
		t.Errorf("backend info: %v", st.BackendInfo)
	}

	// The port is taken: reported, not fatal.
	taken := r.inbound()
	second := newRig(t, func(p *config.Profile) { p.Options.Inbound = taken })
	if st := second.e.Status(); st.Inbound.Active || st.Inbound.Error == "" || second.e.InboundAddr() != nil {
		t.Errorf("second engine on the same port: %+v", st.Inbound)
	}
	r.e.Stop()
	if err := second.e.SetProfile(second.e.Profile()); err != nil {
		t.Fatal(err)
	}
	if st := second.e.Status(); !st.Inbound.Active || st.Inbound.Error != "" {
		t.Errorf("after the port became free: %+v", st.Inbound)
	}

	off := newRig(t, func(p *config.Profile) { p.Options.Inbound = "" })
	if st := off.e.Status(); st.Inbound.Enabled || st.Inbound.Active || off.e.InboundAddr() != nil {
		t.Errorf("listener switched off: %+v", st.Inbound)
	}
}

func TestIdleTimeout(t *testing.T) {
	echo := startEcho(t, "")
	r := newRig(t, func(p *config.Profile) { p.Options.IdleTimeout = 1 })
	c := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	roundTrip(t, c, "then silence")
	start := time.Now()
	expectClosed(t, c)
	if d := time.Since(start); d < 500*time.Millisecond || d > 5*time.Second {
		t.Errorf("idle connection closed after %v, want about 1s", d)
	}
	r.finished(1)
}

func TestStopClosesEverything(t *testing.T) {
	echo := startEcho(t, "")
	r := newRig(t, nil)
	addr := r.inbound()
	c := r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	roundTrip(t, c, "x")
	r.e.Stop()
	expectClosed(t, c)
	if _, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		t.Error("the proxy listener still accepts after Stop")
	}
	r.e.Start() // and it comes back
	c = r.mustTunnel(config.TypeSOCKS5, "127.0.0.1", echo.Port())
	roundTrip(t, c, "again")
}

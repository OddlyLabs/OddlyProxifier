package engine

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/proxytest"
)

func usage(list []Usage, name string) Usage {
	for _, u := range list {
		if u.Name == name {
			return u
		}
	}
	return Usage{}
}

func TestTrafficTotals(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{
		Type: config.TypeSOCKS5,
		Dial: proxytest.Mapper(map[string]string{"app.test:80": echo.Addr()}),
	})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Rules = []config.Rule{
			proxyRule("test names", "px", "*.test"),
			{ID: "b", Name: "ads", Enabled: true, Hosts: []string{"*.ads"}, Action: config.Action{Type: config.ActionBlock}},
		}
	})

	// One open connection shows up as active, with its bytes so far.
	c := r.mustTunnel(config.TypeSOCKS5, "app.test", 80)
	roundTrip(t, c, "hello")
	r.live(1)
	waitFor(t, "live bytes", func() bool { return usage(r.e.Traffic().Routes, "px").Down == 5 })
	tr := r.e.Traffic()
	if u := usage(tr.Routes, "px"); u.Conns != 1 || u.Active != 1 || u.Up != 5 {
		t.Errorf("live route usage: %+v", u)
	}
	_ = c.Close()
	r.finished(1)

	if _, err := r.tunnel(config.TypeSOCKS5, "x.ads", 80); err == nil {
		t.Fatal("the blocked target was reached")
	}
	r.finished(2)

	tr = r.e.Traffic()
	if u := usage(tr.Routes, "px"); u.Conns != 1 || u.Active != 0 || u.Up != 5 || u.Down != 5 {
		t.Errorf("route usage: %+v", u)
	}
	if u := usage(tr.Routes, "(blocked)"); u.Conns != 1 || u.Up != 0 {
		t.Errorf("blocked usage: %+v", u)
	}
	if u := usage(tr.Rules, "test names"); u.Conns != 1 || u.Down != 5 {
		t.Errorf("rule usage: %+v", u)
	}
	if usage(tr.Rules, "ads").Conns != 1 {
		t.Errorf("rules: %+v", tr.Rules)
	}
	var conns int64
	for _, u := range tr.Apps {
		conns += u.Conns
	}
	if conns != 2 {
		t.Errorf("apps: %+v", tr.Apps)
	}
	// Busiest first.
	if tr.Routes[0].Name != "px" {
		t.Errorf("order: %+v", tr.Routes)
	}

	r.e.ResetTraffic()
	if tr = r.e.Traffic(); len(tr.Routes) != 0 || len(tr.Apps) != 0 || len(tr.Points) != 0 {
		t.Errorf("after reset: %+v", tr)
	}
}

func TestTrafficSamples(t *testing.T) {
	var tr traffic
	tr.init()
	now := time.Unix(1000, 0)
	tr.sample(now, 10, 20)
	tr.sample(now.Add(time.Second), 15, 50)
	tr.sample(now.Add(2*time.Second), 5, 50) // a counter that went back never yields a negative rate
	if len(tr.points) != 3 || tr.points[1] != (TrafficPoint{Time: 1001, Up: 5, Down: 30}) || tr.points[2].Up != 0 {
		t.Errorf("points: %+v", tr.points)
	}
	for i := 0; i < trafficSeconds+50; i++ {
		tr.sample(now.Add(time.Duration(i)*time.Second), int64(i), 0)
	}
	if len(tr.points) != trafficSeconds {
		t.Errorf("%d points kept", len(tr.points))
	}
	if last := tr.points[len(tr.points)-1]; last.Time != 1000+trafficSeconds+49 {
		t.Errorf("last point: %+v", last)
	}

	// The tables do not grow without bound.
	for i := 0; i < usageKeys+100; i++ {
		tr.account(ConnInfo{App: "app" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676)), Action: "direct", Up: 1})
	}
	if len(tr.apps) > usageKeys+1 || tr.apps["(other)"] == nil || tr.apps["(other)"].Conns < 99 {
		t.Errorf("%d application keys, other: %+v", len(tr.apps), tr.apps["(other)"])
	}
}

func TestSamplerRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a real second")
	}
	r := newRig(t, nil)
	waitFor(t, "a traffic point", func() bool { return len(r.e.Traffic().Points) > 0 })
}

func TestLogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "engine.log")
	r := newRig(t, func(p *config.Profile) {
		p.Options.LogFile = path
		p.Options.LogLevel = LevelWarn
	})
	r.e.logf(LevelInfo, "quiet line")
	r.e.logf(LevelWarn, "loud line %d", 7)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(data); strings.Contains(s, "quiet line") || !strings.Contains(s, " WARN  loud line 7\n") {
		t.Errorf("log file:\n%s", s)
	}

	// A lower level and another file take effect with the next profile.
	other := filepath.Join(dir, "other.log")
	p := r.e.Profile()
	p.Options.LogFile, p.Options.LogLevel = other, LevelDebug
	if err := r.e.SetProfile(p); err != nil {
		t.Fatal(err)
	}
	r.e.logf(LevelDebug, "detail")
	if data, _ = os.ReadFile(other); !strings.Contains(string(data), "DEBUG detail") {
		t.Errorf("second file:\n%s", data)
	}
	before, _ := os.ReadFile(path)
	r.e.logf(LevelError, "late")
	if after, _ := os.ReadFile(path); len(after) != len(before) {
		t.Error("the first file is still written to")
	}

	// Switched off again: the file is released.
	p = r.e.Profile()
	p.Options.LogFile = ""
	if err := r.e.SetProfile(p); err != nil {
		t.Fatal(err)
	}
	r.e.logf(LevelError, "nowhere")
	if data, _ = os.ReadFile(other); strings.Contains(string(data), "nowhere") {
		t.Error("the file is written to after it was switched off")
	}
	if err := os.Remove(other); err != nil {
		t.Errorf("the file is still held open: %v", err)
	}
}

func TestLogFileRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.log")
	r := newRig(t, func(p *config.Profile) { p.Options.LogFile = path })
	r.e.log.mu.Lock()
	r.e.log.fileSize = logFileSize - 10 // as if the file were nearly full
	r.e.log.mu.Unlock()
	r.e.logf(LevelInfo, "first line of the new file")
	old, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(path)
	if !strings.Contains(string(old), "started") || !strings.Contains(string(cur), "first line of the new file") ||
		strings.Contains(string(cur), "started") {
		t.Errorf("old:\n%s\ncurrent:\n%s", old, cur)
	}
}

func TestLogFileThatCannotBeOpened(t *testing.T) {
	dir := t.TempDir() // a directory is not a file
	r := newRig(t, func(p *config.Profile) { p.Options.LogFile = dir })
	found := false
	for _, le := range r.e.Logs(0) {
		if le.Level == LevelError && strings.HasPrefix(le.Msg, "log file:") {
			found = true
		}
	}
	if !found {
		t.Errorf("no error was logged: %+v", r.e.Logs(0))
	}
}

// Names on the local list are resolved here even when the connection goes
// through a proxy that could resolve them itself.
func TestLocalNamesResolveHere(t *testing.T) {
	echo := startEcho(t, "")
	px := startProxy(t, proxytest.Options{
		Type: config.TypeSOCKS5,
		Dial: func(network, addr string) (net.Conn, error) { return net.Dial("tcp", echo.Addr()) },
	})
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{px.Config("px")}
		p.Default = config.Action{Type: config.ActionProxy, Target: "px"}
	})

	c := r.mustTunnel(config.TypeSOCKS5, "localhost", 80)
	roundTrip(t, c, "ping")
	_ = c.Close()
	r.finished(1)
	if got := px.Targets(); !equalStrings(got, []string{"localhost:80"}) {
		t.Fatalf("without the list the proxy was asked for %q", got)
	}

	p := r.e.Profile()
	p.DNS.LocalNames = []string{"LocalHost", "*.lan"}
	if err := r.e.SetProfile(p); err != nil {
		t.Fatal(err)
	}
	px.Reset()
	c = r.mustTunnel(config.TypeSOCKS5, "localhost", 80)
	roundTrip(t, c, "ping")
	_ = c.Close()
	ci := r.finished(2)[1]
	got := px.Targets()
	if len(got) != 1 || got[0] != "127.0.0.1:80" && got[0] != "[::1]:80" {
		t.Errorf("with the list the proxy was asked for %q", got)
	}
	if ci.Host != "localhost" || ci.IP == "" || ci.Via != "px" {
		t.Errorf("connection: %+v", ci)
	}

	p.DNS.LocalNames = []string{"bad pattern/99"}
	if err := r.e.SetProfile(p); err == nil || !strings.Contains(err.Error(), "local names") {
		t.Errorf("a bad pattern was accepted: %v", err)
	}
}

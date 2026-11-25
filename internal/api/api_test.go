package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/engine"
	"oddlyproxifier/internal/proxytest"
)

const token = "test-token"

type client struct {
	t    *testing.T
	base string
	eng  *engine.Engine
}

func start(t *testing.T) *client {
	t.Helper()
	p := config.Default()
	p.Options.Intercept = false // never touch the machine's network from a test
	p.Options.Inbound = "127.0.0.1:0"
	p.Options.APIToken = token
	eng, err := engine.New(filepath.Join(t.TempDir(), "profile.json"), p)
	if err != nil {
		t.Fatal(err)
	}
	eng.Start()
	t.Cleanup(eng.Stop)
	s, err := Listen(eng, "127.0.0.1:0", token)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(s.Close)
	if want := "http://" + s.Addr().String() + "/#token=" + token; s.URL() != want {
		t.Errorf("URL %q, want %q", s.URL(), want)
	}
	return &client{t: t, base: "http://" + s.Addr().String(), eng: eng}
}

// do sends a request and decodes the JSON answer into out (when not nil).
func (c *client) do(method, path string, body any, out any, edit ...func(q *http.Request)) (*http.Response, string) {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	q, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	q.Header.Set("Authorization", "Bearer "+token)
	for _, e := range edit {
		e(q)
	}
	resp, err := http.DefaultClient.Do(q)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			c.t.Fatalf("%s %s: %v in %q", method, path, err, data)
		}
	}
	return resp, string(data)
}

func TestGuard(t *testing.T) {
	c := start(t)
	for _, tc := range []struct {
		name string
		edit func(q *http.Request)
		code int
		body string
	}{
		{"no token", func(q *http.Request) { q.Header.Del("Authorization") }, 401, "missing or wrong access token"},
		{"wrong token", func(q *http.Request) { q.Header.Set("Authorization", "Bearer nope") }, 401, "missing or wrong access token"},
		{"foreign host", func(q *http.Request) { q.Host = "evil.example" }, 403, "forbidden host"},
		{"foreign host with port", func(q *http.Request) { q.Host = "evil.example:9090" }, 403, "forbidden host"},
		{"localhost", func(q *http.Request) { q.Host = "localhost:9090" }, 200, ""},
	} {
		resp, body := c.do("GET", "/api/status", nil, nil, tc.edit)
		if resp.StatusCode != tc.code || !strings.Contains(body, tc.body) {
			t.Errorf("%s: %d %q", tc.name, resp.StatusCode, body)
		}
	}

	resp, _ := c.do("GET", "/api/status", nil, nil)
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
		resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("API headers: %v", resp.Header)
	}

	// The page itself needs no token, but may not be embedded or load anything foreign.
	resp, body := c.do("GET", "/", nil, nil, func(q *http.Request) { q.Header.Del("Authorization") })
	if resp.StatusCode != 200 || !strings.Contains(strings.ToLower(body), "<!doctype html") {
		t.Errorf("page: %d, %d bytes", resp.StatusCode, len(body))
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP %q", csp)
	}
	if strings.Contains(body, token) {
		t.Error("the page contains the access token")
	}
	resp, _ = c.do("GET", "/", nil, nil, func(q *http.Request) { q.Host = "evil.example" })
	if resp.StatusCode != 403 {
		t.Errorf("page for a foreign host: %d", resp.StatusCode)
	}
}

func TestStatusProfileAndLogs(t *testing.T) {
	c := start(t)
	var st engine.Status
	c.do("GET", "/api/status", nil, &st)
	if st.Version != engine.Version || !st.Inbound.Active || st.Intercept.Enabled || st.ProfilePath == "" {
		t.Errorf("status: %+v", st)
	}

	var p config.Profile
	c.do("GET", "/api/profile", nil, &p)
	if len(p.Rules) != 1 || p.Options.APIToken != token {
		t.Fatalf("profile: %+v", p)
	}
	p.Proxies = []config.Proxy{{ID: "px", Type: config.TypeSOCKS5, Host: "192.0.2.1", Port: 1080}}
	p.Rules = append(p.Rules, config.Rule{ID: "r", Name: "test names", Enabled: true, Hosts: []string{"*.test"},
		Action: config.Action{Type: config.ActionProxy, Target: "px"}})
	p.Options.APIToken = "stolen" // must be ignored
	var saved config.Profile
	if resp, body := c.do("PUT", "/api/profile", &p, &saved); resp.StatusCode != 200 {
		t.Fatalf("PUT profile: %d %s", resp.StatusCode, body)
	}
	if len(saved.Proxies) != 1 || saved.Proxies[0].Name != "192.0.2.1:1080" || saved.Options.APIToken != token {
		t.Errorf("saved profile: %+v", saved)
	}
	onDisk, err := config.Load(c.eng.Path())
	if err != nil || len(onDisk.Rules) != 2 {
		t.Errorf("profile on disk: %+v, %v", onDisk, err)
	}

	p.Rules[1].Action.Target = "nope"
	if resp, body := c.do("PUT", "/api/profile", &p, nil); resp.StatusCode != 422 || !strings.Contains(body, "unknown proxy") {
		t.Errorf("invalid profile: %d %s", resp.StatusCode, body)
	}
	if resp, body := c.do("PUT", "/api/profile", "{not json", nil); resp.StatusCode != 400 || !strings.Contains(body, "bad JSON") {
		t.Errorf("broken JSON: %d %s", resp.StatusCode, body)
	}
	if got := c.eng.Profile(); len(got.Rules) != 2 || got.Rules[1].Action.Target != "px" {
		t.Errorf("a rejected profile changed the active one: %+v", got.Rules)
	}

	var logs []engine.LogEntry
	c.do("GET", "/api/logs", nil, &logs)
	if len(logs) < 2 {
		t.Fatalf("%d log entries", len(logs))
	}
	last := logs[len(logs)-1].Seq
	var later []engine.LogEntry
	c.do("GET", "/api/logs?after="+jsonNum(last), nil, &later)
	if len(later) != 0 {
		t.Errorf("%d entries after the last one", len(later))
	}
}

func jsonNum(n uint64) string { b, _ := json.Marshal(n); return string(b) }

func TestMatch(t *testing.T) {
	c := start(t)
	p := c.eng.Profile()
	p.Proxies = []config.Proxy{{ID: "px", Name: "px", Type: config.TypeSOCKS5, Host: "192.0.2.1", Port: 1080}}
	p.Rules = append(p.Rules,
		config.Rule{ID: "a", Name: "curl only", Enabled: true, Apps: []string{"curl.exe"}, Ports: "443",
			Action: config.Action{Type: config.ActionProxy, Target: "px"}},
		config.Rule{ID: "b", Name: "ads", Enabled: true, Hosts: []string{"*.ads.test"},
			Action: config.Action{Type: config.ActionBlock}})
	type answer struct {
		Rule   string        `json:"rule"`
		Action config.Action `json:"action"`
	}
	for _, tc := range []struct {
		app, host string
		port      int
		rule, typ string
	}{
		{`C:\Tools\CURL.EXE`, "example.test", 443, "curl only", config.ActionProxy},
		{"curl.exe", "example.test", 80, "Default", config.ActionDirect},
		{"", "x.ads.test", 80, "ads", config.ActionBlock},
		{"curl.exe", "10.1.2.3", 443, "Localhost / LAN", config.ActionDirect},
		{"curl.exe", "[::1]", 443, "Localhost / LAN", config.ActionDirect},
	} {
		var a answer
		// The profile under test is not saved.
		c.do("POST", "/api/match", map[string]any{"profile": p, "app": tc.app, "host": tc.host, "port": tc.port}, &a)
		if a.Rule != tc.rule || a.Action.Type != tc.typ {
			t.Errorf("%q %s:%d -> %+v, want %q %s", tc.app, tc.host, tc.port, a, tc.rule, tc.typ)
		}
	}
	var a answer
	c.do("POST", "/api/match", map[string]any{"host": "x.ads.test", "port": 80}, &a)
	if a.Rule != "Default" {
		t.Errorf("active profile: %+v", a)
	}
	p.Default = config.Action{Type: config.ActionProxy, Target: "nope"}
	if resp, _ := c.do("POST", "/api/match", map[string]any{"profile": p, "host": "a.test"}, nil); resp.StatusCode != 422 {
		t.Errorf("invalid profile: %d", resp.StatusCode)
	}
}

func TestCheckAndConnections(t *testing.T) {
	c := start(t)
	echo, err := proxytest.StartEcho("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(echo.Close)
	px, err := proxytest.Start(proxytest.Options{Type: config.TypeSOCKS5})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(px.Close)

	var res engine.CheckResult
	c.do("POST", "/api/check", map[string]any{"proxy": px.Config("tmp"), "target": echo.Addr()}, &res)
	if !res.OK || res.Via != "tmp" || res.Target != echo.Addr() {
		t.Errorf("unsaved proxy: %+v", res)
	}
	if resp, body := c.do("POST", "/api/check", map[string]any{"proxy": map[string]any{"type": "carrier-pigeon", "host": "h", "port": 1}}, nil); resp.StatusCode != 422 {
		t.Errorf("invalid unsaved proxy: %d %s", resp.StatusCode, body)
	}
	c.do("POST", "/api/check", map[string]any{"kind": "proxy", "id": "nope", "target": echo.Addr()}, &res)
	if res.OK || res.Error != "unknown proxy" {
		t.Errorf("unknown proxy: %+v", res)
	}
	p := c.eng.Profile()
	p.Proxies = []config.Proxy{px.Config("px")}
	if err := c.eng.SetProfile(p); err != nil {
		t.Fatal(err)
	}
	c.do("POST", "/api/check", map[string]any{"kind": "proxy", "id": "px", "target": echo.Addr()}, &res)
	if !res.OK || res.Via != "px" {
		t.Errorf("saved proxy: %+v", res)
	}

	var list struct {
		Active []engine.ConnInfo `json:"active"`
		Recent []engine.ConnInfo `json:"recent"`
	}
	_, body := c.do("GET", "/api/connections", nil, &list)
	if len(list.Active) != 0 || len(list.Recent) != 0 || !strings.Contains(body, `"active":[],"recent":[]`) {
		t.Errorf("connections: %s", body)
	}
	if _, body := c.do("DELETE", "/api/connections/7", nil, nil); !strings.Contains(body, `"ok":false`) {
		t.Errorf("closing an unknown connection: %s", body)
	}
	if resp, body := c.do("DELETE", "/api/connections/seven", nil, nil); resp.StatusCode != 400 || !strings.Contains(body, "bad id") {
		t.Errorf("bad id: %d %s", resp.StatusCode, body)
	}
	if _, body := c.do("DELETE", "/api/connections", nil, nil); !strings.Contains(body, `"ok":true`) {
		t.Errorf("close all: %s", body)
	}
}

func TestDriverEndpoints(t *testing.T) {
	c := start(t)
	var info map[string]any
	if resp, _ := c.do("GET", "/api/driver", nil, &info); resp.StatusCode != 200 {
		t.Errorf("driver info: %d", resp.StatusCode)
	}
	// Only an operation that does not exist: real ones change the machine.
	if resp, body := c.do("POST", "/api/driver/self-destruct", nil, nil); resp.StatusCode != 500 || !strings.Contains(body, `"error"`) {
		t.Errorf("unknown driver operation: %d %s", resp.StatusCode, body)
	}
	if resp, _ := c.do("GET", "/api/nothing-here", nil, nil); resp.StatusCode != 404 {
		t.Errorf("unknown endpoint: %d", resp.StatusCode)
	}
}

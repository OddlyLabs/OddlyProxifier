package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"oddlyproxifier/internal/config"
)

func TestClientFor(t *testing.T) {
	p := config.Default()
	p.Options.APIToken = "tok"
	for _, c := range []struct{ profile, flag, base string }{
		{"127.0.0.1:9090", "", "http://127.0.0.1:9090"},
		{"0.0.0.0:9090", "", "http://127.0.0.1:9090"},
		{"[::]:9090", "", "http://127.0.0.1:9090"},
		{":8080", "", "http://127.0.0.1:8080"},
		{"127.0.0.1:9090", "192.168.1.5:7000", "http://192.168.1.5:7000"},
		{"[::1]:9090", "", "http://[::1]:9090"},
		{"garbage", "", "http://127.0.0.1:9090"},
	} {
		p.Options.API = c.profile
		got := clientFor(p, c.flag)
		if got.base != c.base || got.url != c.base+"/#token=tok" || got.token != "tok" {
			t.Errorf("clientFor(%q, %q) = %+v", c.profile, c.flag, got)
		}
	}
}

func TestTrayClientTalksToTheAPI(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/status":
			_, _ = w.Write([]byte(`{"version":"x","intercept":{"enabled":true,"active":true},"stats":{"active":3}}`))
		case "/api/intercept":
			var in map[string]bool
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["enabled"] {
				gotBody = "on"
			} else {
				gotBody = "off"
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, `{"error":"no"}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := trayClient{base: srv.URL, token: "tok"}
	if !c.alive() {
		t.Fatal("the engine was not found")
	}
	st, err := c.status(context.Background())
	if err != nil || !st.Intercept.Enabled || st.Stats.Active != 3 || gotAuth != "Bearer tok" {
		t.Errorf("status: %+v %v, auth %q", st, err, gotAuth)
	}
	if err := c.setIntercept(context.Background(), false); err != nil || gotBody != "off" {
		t.Errorf("switch: %v, body %q", err, gotBody)
	}
	if err := c.call(context.Background(), "GET", "/api/none", nil, nil); err == nil {
		t.Error("an error status was taken for success")
	}
	srv.Close()
	if c.alive() {
		t.Error("a closed server counts as alive")
	}
}

func TestWantTray(t *testing.T) {
	if _, err := wantTray("sometimes", false); err == nil {
		t.Error("a bad mode was accepted")
	}
	if on, err := wantTray("off", false); on || err != nil {
		t.Errorf("off: %v %v", on, err)
	}
	// Under "go test" nobody double-clicked, and a service never gets an icon.
	if on, err := wantTray("auto", false); on || err != nil {
		t.Errorf("auto: %v %v", on, err)
	}
	if on, _ := wantTray("auto", true); on {
		t.Error("a service wants an icon")
	}
}

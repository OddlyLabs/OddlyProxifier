package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/engine"
)

// trayClient is what the notification-area icon knows about an engine: where
// its API is and how to open its web interface. The icon is a plain API
// client, so it works the same for the engine in this process and for one
// that runs as a service.
type trayClient struct {
	base  string // http://host:port
	token string
	url   string // the web interface, token included
}

// clientFor addresses the engine a profile describes. apiAddr overrides the
// profile's listen address.
func clientFor(prof *config.Profile, apiAddr string) trayClient {
	addr := prof.Options.API
	if apiAddr != "" {
		addr = apiAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = "127.0.0.1", "9090"
	}
	if ip, err := netip.ParseAddr(host); host == "" || err == nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	base := "http://" + net.JoinHostPort(host, port)
	return trayClient{base: base, token: prof.Options.APIToken, url: base + "/#token=" + prof.Options.APIToken}
}

var trayHTTP = &http.Client{
	Timeout: 5 * time.Second,
	// The engine is on this machine: a system-wide proxy setting must not
	// send the request, and the token with it, anywhere else.
	Transport: &http.Transport{Proxy: nil},
}

func (c trayClient) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := trayHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(data))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c trayClient) status(ctx context.Context) (engine.Status, error) {
	var st engine.Status
	err := c.call(ctx, http.MethodGet, "/api/status", nil, &st)
	return st, err
}

// alive reports whether an engine answers there and accepts our token.
func (c trayClient) alive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	_, err := c.status(ctx)
	return err == nil
}

func (c trayClient) setIntercept(ctx context.Context, on bool) error {
	return c.call(ctx, http.MethodPost, "/api/intercept", map[string]bool{"enabled": on}, nil)
}

// Package api serves the control API and the embedded web interface.
package api

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/engine"
	"oddlyproxifier/internal/intercept"
	"oddlyproxifier/internal/rules"
)

//go:embed web
var webFS embed.FS

type Server struct {
	eng   *engine.Engine
	token string
	srv   *http.Server
	ln    net.Listener
}

// Listen binds addr. token protects every /api/ endpoint.
func Listen(eng *engine.Engine, addr, token string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{eng: eng, token: token, ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/profile", s.getProfile)
	mux.HandleFunc("PUT /api/profile", s.putProfile)
	mux.HandleFunc("GET /api/profiles", s.listProfiles)
	mux.HandleFunc("PUT /api/profiles/{name}", s.saveProfile)
	mux.HandleFunc("POST /api/profiles/{name}/activate", s.activateProfile)
	mux.HandleFunc("DELETE /api/profiles/{name}", s.deleteProfile)
	mux.HandleFunc("GET /api/export", s.exportProfile)
	mux.HandleFunc("POST /api/import", s.importProfile)
	mux.HandleFunc("POST /api/intercept", s.setIntercept)
	mux.HandleFunc("GET /api/connections", s.connections)
	mux.HandleFunc("DELETE /api/connections", s.closeAll)
	mux.HandleFunc("DELETE /api/connections/{id}", s.closeOne)
	mux.HandleFunc("GET /api/logs", s.logs)
	mux.HandleFunc("GET /api/traffic", s.traffic)
	mux.HandleFunc("DELETE /api/traffic", s.resetTraffic)
	mux.HandleFunc("POST /api/check", s.check)
	mux.HandleFunc("POST /api/match", s.match)
	mux.HandleFunc("GET /api/driver", s.driver)
	mux.HandleFunc("POST /api/driver/{op}", s.driverOp)
	web, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServerFS(web))
	s.srv = &http.Server{
		Handler:           s.guard(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// Addr is the address the server is bound to.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// URL is the address of the web interface, including the access token.
func (s *Server) URL() string {
	host, port, _ := net.SplitHostPort(s.ln.Addr().String())
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/#token=" + s.token
}

func (s *Server) Serve() error {
	err := s.srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}

// guard rejects cross-site requests and unauthenticated API calls.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DNS rebinding: a page on evil.example that resolves to 127.0.0.1
		// still sends "Host: evil.example".
		if !localHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeErr(w, http.StatusUnauthorized, "missing or wrong access token")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		next.ServeHTTP(w, r)
	})
}

func localHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	// Address literals cannot be rebound.
	_, err := netip.ParseAddr(host)
	return err == nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	data, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(data, v)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return false
	}
	return true
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.eng.Status()) }

func (s *Server) getProfile(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.eng.Profile()) }

func (s *Server) putProfile(w http.ResponseWriter, r *http.Request) {
	p := &config.Profile{}
	if !readJSON(w, r, p) {
		return
	}
	p.Normalize()
	// The token and the API address are fixed for the lifetime of the
	// process; changing them here would lock the interface out.
	cur := s.eng.Profile()
	p.Options.APIToken = cur.Options.APIToken
	if err := s.eng.SetProfile(p); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, s.eng.Profile())
}

func (s *Server) connections(w http.ResponseWriter, _ *http.Request) {
	active, recent := s.eng.Connections()
	writeJSON(w, map[string]any{"active": active, "recent": recent})
}

func (s *Server) closeAll(w http.ResponseWriter, _ *http.Request) {
	s.eng.CloseAll()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) closeOne(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	writeJSON(w, map[string]bool{"ok": s.eng.CloseConn(id)})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	writeJSON(w, s.eng.Logs(after))
}

func (s *Server) traffic(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.eng.Traffic()) }

func (s *Server) resetTraffic(w http.ResponseWriter, _ *http.Request) {
	s.eng.ResetTraffic()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Kind   string        `json:"kind"` // proxy | chain
		ID     string        `json:"id"`
		Proxy  *config.Proxy `json:"proxy"` // an unsaved definition
		Target string        `json:"target"`
	}
	if !readJSON(w, r, &q) {
		return
	}
	if q.Target == "" {
		q.Target = "www.gstatic.com:80"
	}
	if q.Proxy != nil {
		tmp := &config.Profile{Proxies: []config.Proxy{*q.Proxy}}
		tmp.Normalize()
		if err := tmp.Validate(); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeJSON(w, s.eng.CheckProxy(r.Context(), tmp.Proxies[0], q.Target))
		return
	}
	writeJSON(w, s.eng.Check(r.Context(), q.Kind, q.ID, q.Target))
}

// match answers "which rule would this connection hit" for a profile that
// may not be saved yet.
func (s *Server) match(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Profile *config.Profile `json:"profile"`
		App     string          `json:"app"`
		Host    string          `json:"host"`
		Port    int             `json:"port"`
	}
	if !readJSON(w, r, &q) {
		return
	}
	p := q.Profile
	if p == nil {
		p = s.eng.Profile()
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	set, err := rules.Compile(p)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	req := rules.Request{App: q.App, Host: q.Host, Port: q.Port}
	if ip, err := netip.ParseAddr(strings.Trim(q.Host, "[]")); err == nil {
		req.Host, req.IP = "", ip.Unmap() // an address literal is matched as an address
	}
	name, action := set.Match(req)
	writeJSON(w, map[string]any{"rule": name, "action": action})
}

func (s *Server) driver(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, intercept.DriverInfo())
}

func (s *Server) driverOp(w http.ResponseWriter, r *http.Request) {
	if err := intercept.DriverOp(r.PathValue("op")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// A freshly started driver should be picked up right away.
	if err := s.eng.SetProfile(s.eng.Profile()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, intercept.DriverInfo())
}

// setIntercept is the quick switch: interception on or off, nothing else
// in the profile touched.
func (s *Server) setIntercept(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Enabled == nil {
		writeErr(w, http.StatusBadRequest, `expected {"enabled": true} or {"enabled": false}`)
		return
	}
	if err := s.eng.SetIntercept(*in.Enabled); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, s.eng.Status())
}

package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"oddlyproxifier/internal/config"
)

// send writes a raw request to the proxy listener and reads one response.
func send(t *testing.T, c net.Conn, br *bufio.Reader, text string) (*http.Response, string) {
	t.Helper()
	if _, err := io.WriteString(c, text); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("response to %q: %v", strings.SplitN(text, "\r\n", 2)[0], err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

func get(t *testing.T, cl *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := cl.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestHTTPForwardHeaders(t *testing.T) {
	var mu sync.Mutex
	var seen []*http.Request
	up := startRawHTTP(t, func(x *rawReq) bool {
		mu.Lock()
		seen = append(seen, x.q)
		mu.Unlock()
		x.ok("fine")
		return true
	})
	r := newRig(t, nil)
	c := r.raw()
	br := bufio.NewReader(c)

	resp, body := send(t, c, br, "GET http://"+up.addr()+"/path?x=1 HTTP/1.1\r\nHost: "+up.addr()+
		"\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic eDp5\r\nX-Custom: kept\r\n\r\n")
	if resp.StatusCode != 200 || body != "fine" {
		t.Fatalf("status %d, body %q", resp.StatusCode, body)
	}
	resp, _ = send(t, c, br, "GET http://"+up.addr()+"/two HTTP/1.1\r\nHost: "+up.addr()+"\r\nUser-Agent: mine/1.0\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Fatalf("second request: status %d", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("the server saw %d requests", len(seen))
	}
	q := seen[0]
	if q.RequestURI != "/path?x=1" || q.Host != up.addr() || q.Header.Get("X-Custom") != "kept" {
		t.Errorf("request line %q, host %q, header %v", q.RequestURI, q.Host, q.Header)
	}
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Via", "X-Forwarded-For"} {
		if _, ok := q.Header[h]; ok {
			t.Errorf("header %s reached the server", h)
		}
	}
	if ua := q.Header.Get("User-Agent"); ua != "" {
		t.Errorf("a User-Agent was invented: %q", ua)
	}
	if ua := seen[1].Header.Get("User-Agent"); ua != "mine/1.0" {
		t.Errorf("User-Agent %q", ua)
	}
	if up.conns.Load() != 1 {
		t.Errorf("%d upstream connections, want 1", up.conns.Load())
	}
}

func TestHTTPForwardKeepAlive(t *testing.T) {
	up := startRawHTTP(t, func(x *rawReq) bool {
		x.ok(fmt.Sprintf("%s #%d", x.q.URL.Path, x.nth))
		return true
	})
	r := newRig(t, nil)
	cl := r.httpClient()
	for i := 1; i <= 3; i++ {
		code, body := get(t, cl, fmt.Sprintf("%sr%d", up.url(), i))
		if want := fmt.Sprintf("/r%d #%d", i, i); code != 200 || body != want {
			t.Errorf("request %d: %d %q, want %q", i, code, body, want)
		}
	}
	if up.conns.Load() != 1 {
		t.Errorf("%d upstream connections, want 1", up.conns.Load())
	}
	if st := r.e.Status().Stats; st.Total != 1 || st.Active != 1 {
		t.Errorf("stats: %+v", st)
	}
	cl.CloseIdleConnections()
	ci := r.finished(1)[0]
	if ci.Inbound != "http" || ci.State != StateClosed || ci.Up == 0 || ci.Down == 0 || ci.Port != up.port() {
		t.Errorf("%+v", ci)
	}
}

func TestHTTPForwardBodies(t *testing.T) {
	up := startRawHTTP(t, func(x *rawReq) bool {
		if x.q.Header.Get("Expect") != "" {
			x.ok("expectation leaked")
			return true
		}
		_, _ = fmt.Fprintf(x.c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(x.body))
		if x.q.Method != http.MethodHead {
			_, _ = x.c.Write(x.body)
		}
		return true
	})
	r := newRig(t, nil)
	cl := r.httpClient()
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB

	post := func(name string, body io.Reader, expect bool) {
		t.Helper()
		q, _ := http.NewRequest(http.MethodPost, up.url(), body)
		got100 := false
		if expect {
			q.Header.Set("Expect", "100-continue")
			q = q.WithContext(httptrace.WithClientTrace(q.Context(), &httptrace.ClientTrace{
				Got100Continue: func() { got100 = true },
			}))
		}
		start := time.Now()
		resp, err := cl.Do(q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer resp.Body.Close()
		back, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !bytes.Equal(back, big) {
			t.Errorf("%s: status %d, %d bytes back, want %d", name, resp.StatusCode, len(back), len(big))
		}
		if expect && (!got100 || time.Since(start) > 5*time.Second) {
			t.Errorf("%s: 100 Continue seen: %v, took %v", name, got100, time.Since(start))
		}
	}
	post("known length", bytes.NewReader(big), false)
	post("chunked", io.MultiReader(bytes.NewReader(big)), false)
	post("expect 100-continue", bytes.NewReader(big), true)

	// HEAD keeps its Content-Length and leaves the connection usable.
	resp, err := cl.Head(up.url())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.ContentLength != 0 {
		t.Errorf("HEAD: %d, length %d", resp.StatusCode, resp.ContentLength)
	}
	if code, _ := get(t, cl, up.url()); code != 200 {
		t.Errorf("GET after HEAD: %d", code)
	}
}

func TestHTTPForwardInterim(t *testing.T) {
	up := startRawHTTP(t, func(x *rawReq) bool {
		_, _ = io.WriteString(x.c, "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
		x.ok("done")
		return true
	})
	r := newRig(t, nil)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		c := r.raw()
		br := bufio.NewReader(c)
		text := method + " http://" + up.addr() + "/ HTTP/1.1\r\nHost: " + up.addr() + "\r\n"
		if method == http.MethodPost {
			text += "Content-Length: 2\r\n\r\nhi"
		} else {
			text += "\r\n"
		}
		if _, err := io.WriteString(c, text); err != nil {
			t.Fatal(err)
		}
		tp := textproto.NewReader(br)
		line, err := tp.ReadLine()
		if err != nil || line != "HTTP/1.1 103 Early Hints" {
			t.Fatalf("%s: first line %q, %v", method, line, err)
		}
		h, err := tp.ReadMIMEHeader()
		if err != nil || h.Get("Link") != "</style.css>; rel=preload" || len(h) != 1 {
			t.Errorf("%s: interim header %v, %v", method, h, err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: final response %v, %v", method, resp, err)
		}
		_ = resp.Body.Close()
	}
}

func TestHTTPForwardUpgrade(t *testing.T) {
	up := startRawHTTP(t, func(x *rawReq) bool {
		_, _ = io.WriteString(x.c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\nwelcome ")
		_, _ = io.Copy(x.c, x.br)
		return false
	})
	r := newRig(t, nil)
	c := r.raw()
	br := bufio.NewReader(c)
	_, _ = io.WriteString(c, "GET http://"+up.addr()+"/ws HTTP/1.1\r\nHost: "+up.addr()+"\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil || line != "HTTP/1.1 101 Switching Protocols" {
		t.Fatalf("first line %q, %v", line, err)
	}
	h, _ := tp.ReadMIMEHeader()
	if h.Get("Upgrade") != "echo" || h.Get("Content-Length") != "" {
		t.Errorf("header %v", h)
	}
	_, _ = io.WriteString(c, "frames")
	buf := make([]byte, len("welcome frames"))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "welcome frames" {
		t.Fatalf("tunnel: %q, %v", buf, err)
	}
	_ = c.Close()
	if ci := r.finished(1)[0]; ci.State != StateClosed || ci.Inbound != "http" {
		t.Errorf("%+v", ci)
	}
}

// Servers close connections whenever they like; the client must not notice.
func TestHTTPForwardUpstreamCloses(t *testing.T) {
	up := startRawHTTP(t, func(x *rawReq) bool {
		x.ok("bye")
		return false
	})
	r := newRig(t, nil)
	cl := r.httpClient()
	for i := 0; i < 2; i++ {
		if code, body := get(t, cl, up.url()); code != 200 || body != "bye" {
			t.Errorf("GET %d: %d %q", i, code, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	resp, err := cl.Post(up.url(), "text/plain", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || up.conns.Load() != 3 {
		t.Errorf("POST: %d, %d upstream connections (want 3)", resp.StatusCode, up.conns.Load())
	}
}

// A server that drops the connection in the very moment the next request
// arrives: safe requests are repeated, others are reported.
func TestHTTPForwardRetry(t *testing.T) {
	up := startRawHTTP(t, func(x *rawReq) bool {
		if x.nth == 2 {
			return false
		}
		x.ok("ok")
		return true
	})
	r := newRig(t, nil)
	c := r.raw()
	br := bufio.NewReader(c)
	req := func(method, extra string) string {
		return method + " http://" + up.addr() + "/ HTTP/1.1\r\nHost: " + up.addr() + "\r\n" + extra + "\r\n"
	}
	for i := 0; i < 2; i++ {
		if resp, body := send(t, c, br, req("GET", "")); resp.StatusCode != 200 || body != "ok" {
			t.Fatalf("GET %d: %d %q", i, resp.StatusCode, body)
		}
	}
	if up.conns.Load() != 2 {
		t.Errorf("%d upstream connections, want 2", up.conns.Load())
	}
	resp, body := send(t, c, br, req("POST", "Content-Length: 1\r\n")+"x")
	if resp.StatusCode != 502 || !strings.Contains(body, "upstream closed the connection") {
		t.Errorf("POST: %d %q", resp.StatusCode, body)
	}
	expectClosed(t, c)
}

func TestHTTPForwardErrors(t *testing.T) {
	bad := refuser(t)
	r := newRig(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{bad.Config("bad")}
		p.Rules = []config.Rule{blockRule("no entry", "203.0.113.9"), proxyRule("dead end", "bad", "203.0.113.10")}
	})
	for _, tc := range []struct {
		text string
		code int
		body string
	}{
		{"GET http://203.0.113.9/ HTTP/1.1\r\nHost: 203.0.113.9\r\n\r\n", 403, "blocked by rule"},
		{"GET http://203.0.113.10/ HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n", 502, "connection refused"},
		{"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 400, "this is a proxy server"},
		{"GET http://203.0.113.9:99999/ HTTP/1.1\r\nHost: x\r\n\r\n", 400, "bad target"},
	} {
		c := r.raw()
		resp, body := send(t, c, bufio.NewReader(c), tc.text)
		if resp.StatusCode != tc.code || !strings.Contains(body, tc.body) {
			t.Errorf("%q: %d %q, want %d %q", tc.text, resp.StatusCode, body, tc.code, tc.body)
		}
		expectClosed(t, c)
	}
}

func TestHTTPForwardBodyFraming(t *testing.T) {
	up := startRawHTTP(t, func(x *rawReq) bool {
		if x.q.URL.Path == "/chunked" {
			_, _ = io.WriteString(x.c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
			return true
		}
		_, _ = io.WriteString(x.c, "HTTP/1.1 200 OK\r\n\r\nuntil the end")
		return false
	})
	r := newRig(t, nil)

	// No length at all: the body ends with the connection, on both sides.
	c := r.raw()
	resp, body := send(t, c, bufio.NewReader(c), "GET http://"+up.addr()+"/ HTTP/1.1\r\nHost: "+up.addr()+"\r\n\r\n")
	if resp.StatusCode != 200 || body != "until the end" {
		t.Errorf("unframed body: %d %q", resp.StatusCode, body)
	}

	// HTTP/1.0 clients do not understand chunks.
	c = r.raw()
	_, _ = io.WriteString(c, "GET http://"+up.addr()+"/chunked HTTP/1.0\r\n\r\n")
	raw, _ := io.ReadAll(c)
	head, rest, _ := strings.Cut(string(raw), "\r\n\r\n")
	if rest != "hello world" || strings.Contains(strings.ToLower(head), "chunked") {
		t.Errorf("HTTP/1.0 client got %q", raw)
	}

	// HTTP/1.1 clients get them as they are.
	cl := r.httpClient()
	if code, body := get(t, cl, up.url()+"chunked"); code != 200 || body != "hello world" {
		t.Errorf("chunked: %d %q", code, body)
	}
}

// A rule change applies to the next request of a client that stays connected.
func TestHTTPForwardProfileChange(t *testing.T) {
	up := startRawHTTP(t, func(x *rawReq) bool { x.ok("ok"); return true })
	r := newRig(t, nil)
	cl := r.httpClient()
	if code, _ := get(t, cl, up.url()); code != 200 {
		t.Fatalf("status %d", code)
	}
	p := r.e.Profile()
	p.Rules = []config.Rule{blockRule("closed now", "127.0.0.1")}
	if err := r.e.SetProfile(p); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, cl, up.url()); code != 403 || !strings.Contains(body, "blocked by rule") {
		t.Errorf("after the rule change: %d %q", code, body)
	}
}

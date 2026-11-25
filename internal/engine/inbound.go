package engine

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"oddlyproxifier/internal/netx"
	"oddlyproxifier/internal/procinfo"
	"oddlyproxifier/internal/sniff"
)

const handshakeTimeout = 15 * time.Second

// serveInbound handles one client of the explicit proxy port. The protocol
// is told apart by the first byte: 5 = SOCKS5, 4 = SOCKS4/4a, else HTTP.
func (e *Engine) serveInbound(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(c, 4096)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	base := &request{client: c}
	base.src, _ = addrPort(c.RemoteAddr())
	if local, ok := addrPort(c.LocalAddr()); ok && base.src.Addr().IsLoopback() {
		base.pid, base.app = procinfo.Find(base.src, local)
	}
	switch first[0] {
	case 5:
		e.serveSocks5(c, br, base)
	case 4:
		e.serveSocks4(c, br, base)
	default:
		e.serveHTTP(c, br, base)
	}
}

// drain returns the bytes the client sent beyond the handshake.
func drain(c net.Conn, br *bufio.Reader) net.Conn {
	n := br.Buffered()
	if n == 0 {
		return c
	}
	pre := make([]byte, n)
	_, _ = io.ReadFull(br, pre)
	return netx.WithPrefix(c, pre)
}

// setTarget fills in the destination of a request from host, which may be a
// name or an address literal.
func setTarget(req *request, host string, port int) {
	req.port = port
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		req.ip = ip.Unmap()
	} else {
		req.host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
}

// run routes a fully parsed proxy request and relays it. reply tells the
// client whether the tunnel is up.
func (e *Engine) run(c net.Conn, br *bufio.Reader, req *request, reply func(err error) error) {
	st := e.st.Load()
	if f := e.fake.Load(); f != nil && req.ip.IsValid() && f.Contains(req.ip) {
		if name, ok := f.Lookup(req.ip); ok {
			req.host, req.fake = name, true
		}
	}
	var s *session
	client := drain(c, br)
	if req.host == "" && st.prof.DNS.Sniff {
		client = sniff.Tap(client, func(h string) { s.setHost(h) })
	}
	req.client = c
	s, remote, err := e.open(st, req)
	if err != nil {
		_ = reply(err)
		return
	}
	if err := reply(nil); err != nil {
		_ = remote.Close()
		e.finish(s, StateFailed, fmt.Errorf("client went away: %w", err))
		return
	}
	_ = c.SetDeadline(time.Time{})
	e.pipe(st, s, client, remote)
}

// ---------------------------------------------------------------- SOCKS5

func (e *Engine) serveSocks5(c net.Conn, br *bufio.Reader, req *request) {
	req.inbound = "socks5"
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:2]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if !strings.ContainsRune(string(methods), 0) {
		_, _ = c.Write([]byte{5, 0xFF})
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	var host string
	switch hdr[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(a).String()
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return
		}
		host = netip.AddrFrom16(a).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil || l == 0 {
			return
		}
		name := make([]byte, l)
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	default:
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return
	}
	if hdr[1] == 3 && e.st.Load().prof.Options.UDP {
		// UDP ASSOCIATE. The address in the request is where the client means
		// to send from; hardly any client knows it, so it is not relied upon.
		e.serveUDP(c, br, req)
		return
	}
	if hdr[1] != 1 { // no BIND, and no UDP ASSOCIATE where that is switched off
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	setTarget(req, host, int(binary.BigEndian.Uint16(pb[:])))
	e.run(c, br, req, func(err error) error {
		code := byte(0)
		switch {
		case err == nil:
		case errors.Is(err, errBlocked):
			code = 2
		default:
			code = 5
		}
		_, werr := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		return werr
	})
}

// ---------------------------------------------------------------- SOCKS4

func readCString(br *bufio.Reader, max int) (string, error) {
	var b []byte
	for {
		ch, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if ch == 0 {
			return string(b), nil
		}
		if len(b) >= max {
			return "", errors.New("string too long")
		}
		b = append(b, ch)
	}
}

func (e *Engine) serveSocks4(c net.Conn, br *bufio.Reader, req *request) {
	req.inbound = "socks4"
	var hdr [8]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	if _, err := readCString(br, 255); err != nil { // user id, ignored
		return
	}
	port := int(binary.BigEndian.Uint16(hdr[2:4]))
	host := netip.AddrFrom4([4]byte(hdr[4:8])).String()
	if hdr[4] == 0 && hdr[5] == 0 && hdr[6] == 0 && hdr[7] != 0 { // SOCKS4a
		name, err := readCString(br, 255)
		if err != nil || name == "" {
			return
		}
		host = name
	}
	if hdr[1] != 1 {
		_, _ = c.Write([]byte{0, 0x5B, 0, 0, 0, 0, 0, 0})
		return
	}
	setTarget(req, host, port)
	e.run(c, br, req, func(err error) error {
		code := byte(0x5A)
		if err != nil {
			code = 0x5B
		}
		_, werr := c.Write([]byte{0, code, 0, 0, 0, 0, 0, 0})
		return werr
	})
}

// ------------------------------------------------------------------ HTTP

func httpError(c net.Conn, code int, msg string) {
	body := msg + "\n"
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

func splitHostPort(hostport string, defPort int) (string, int, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port given.
		return strings.Trim(hostport, "[]"), defPort, nil
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("bad port")
	}
	return host, port, nil
}

// countConn accounts the bytes of a forwarded HTTP exchange to its session.
type countConn struct {
	net.Conn
	s *session
}

func (c countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.s.down.Add(int64(n))
	return n, err
}

func (c countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.s.up.Add(int64(n))
	return n, err
}

var hopHeaders = []string{
	"Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer",
}

// errClientGone marks a failure on the client's side of a forwarded exchange.
var errClientGone = errors.New("client went away")

// serveHTTP implements an HTTP proxy: CONNECT tunnels, and plain requests
// with an absolute URI which are forwarded one by one, re-using the upstream
// connection while consecutive requests go to the same server.
func (e *Engine) serveHTTP(c net.Conn, br *bufio.Reader, base *request) {
	base.inbound = "http"
	var (
		up    net.Conn
		upBR  *bufio.Reader
		upKey string // host:port the upstream connection leads to
		upSt  *state // routing snapshot it was opened under
		sess  *session
	)
	closeUp := func(err error) {
		if up == nil {
			return
		}
		_ = up.Close()
		state := StateClosed
		if err != nil {
			state = StateFailed
		}
		e.finish(sess, state, err)
		up, upBR, upKey, upSt, sess = nil, nil, "", nil, nil
	}
	defer closeUp(nil)

	// exchange sends r upstream and returns the final response. Interim
	// responses (103 Early Hints and the like) are passed on as they come.
	exchange := func(r *http.Request) (*http.Response, error) {
		if err := r.Write(up); err != nil {
			return nil, err
		}
		for {
			resp, err := http.ReadResponse(upBR, r)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode/100 != 1 || resp.StatusCode == http.StatusSwitchingProtocols {
				return resp, nil
			}
			if err := writeHead(c, resp); err != nil {
				return nil, errClientGone
			}
		}
	}

	for {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		r, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		st := e.st.Load() // a profile change applies from the next request on

		if r.Method == http.MethodConnect {
			closeUp(nil)
			host, port, err := splitHostPort(r.Host, 443)
			if err != nil || host == "" {
				httpError(c, http.StatusBadRequest, "bad CONNECT target")
				return
			}
			req := *base
			setTarget(&req, host, port)
			e.run(c, br, &req, func(err error) error {
				switch {
				case err == nil:
					_, werr := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
					return werr
				case errors.Is(err, errBlocked):
					httpError(c, http.StatusForbidden, "blocked by rule")
				default:
					httpError(c, http.StatusBadGateway, err.Error())
				}
				return nil
			})
			return
		}

		if !r.URL.IsAbs() || r.URL.Host == "" || !strings.EqualFold(r.URL.Scheme, "http") {
			httpError(c, http.StatusBadRequest, "this is a proxy server: absolute http:// URL or CONNECT expected")
			return
		}
		host, port, err := splitHostPort(r.URL.Host, 80)
		if err != nil || host == "" {
			httpError(c, http.StatusBadRequest, "bad target")
			return
		}
		key := net.JoinHostPort(host, strconv.Itoa(port))
		if up != nil && (key != upKey || st != upSt || !idleAlive(up, upBR)) {
			// Another server, rules that changed in the meantime, or a
			// connection the server has closed while it sat idle.
			closeUp(nil)
		}
		connect := func() bool {
			req := *base
			setTarget(&req, host, port)
			req.client = c
			s, remote, err := e.open(st, &req)
			if err != nil {
				if errors.Is(err, errBlocked) {
					httpError(c, http.StatusForbidden, "blocked by rule")
				} else {
					httpError(c, http.StatusBadGateway, err.Error())
				}
				return false
			}
			sess, upKey, upSt = s, key, st
			up = countConn{remote, s}
			upBR = bufio.NewReader(up)
			return true
		}
		reused := up != nil
		if !reused && !connect() {
			return
		}

		// Forward in origin form, without the hop-by-hop proxy headers and
		// without adding anything of our own.
		for _, h := range hopHeaders {
			r.Header.Del(h)
		}
		if _, ok := r.Header["User-Agent"]; !ok {
			r.Header["User-Agent"] = []string{""} // keeps net/http from inventing one
		}
		r.RequestURI = ""
		if strings.EqualFold(r.Header.Get("Expect"), "100-continue") {
			// The body is forwarded in one piece, so the expectation is met
			// here; the client would otherwise sit out its timeout first.
			r.Header.Del("Expect")
			if _, err := io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return
			}
		}

		resp, err := exchange(r)
		if err != nil && err != errClientGone && reused && replayable(r) {
			// The server closed the connection just as the request went out.
			// Nothing has been answered yet: once more on a fresh one.
			closeUp(nil)
			if !connect() {
				return
			}
			resp, err = exchange(r)
		}
		if err != nil {
			if err != errClientGone {
				closeUp(err)
				httpError(c, http.StatusBadGateway, "upstream closed the connection")
			}
			return
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			// Protocol upgrade (WebSocket): from here on it is a raw tunnel.
			if err := writeHead(c, resp); err != nil {
				return
			}
			s, remote := sess, netx.WithPrefix(up.(countConn).Conn, peekAll(upBR))
			up, upBR, upKey, upSt, sess = nil, nil, "", nil, nil
			e.pipe(st, s, drain(c, br), remote)
			return
		}
		if !r.ProtoAtLeast(1, 1) && len(resp.TransferEncoding) > 0 {
			// An HTTP/1.0 client cannot read chunks: its body ends with the
			// connection instead.
			resp.TransferEncoding, resp.ContentLength, resp.Close = nil, -1, true
		}
		werr := resp.Write(c)
		_ = resp.Body.Close()
		if werr != nil || resp.Close || r.Close {
			// A response that ends with the connection has to end ours as well:
			// that is the only way the client can tell where the body stops.
			return
		}
	}
}

// writeHead passes on the status line and header of a response that has no
// body (1xx), exactly as the server sent them.
func writeHead(w io.Writer, resp *http.Response) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", resp.Status)
	_ = resp.Header.Write(&b)
	b.WriteString("\r\n")
	_, err := w.Write(b.Bytes())
	return err
}

// idleAlive tells whether an upstream connection that sat idle between two
// requests can take another one. Servers close idle connections whenever they
// like, and a request written into a closed one is lost.
func idleAlive(c net.Conn, br *bufio.Reader) bool {
	if br.Buffered() > 0 {
		return false // the server said something nobody asked for
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
	_, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() // anything else: closed, or talking out of turn
}

// replayable reports whether r can be sent a second time without harm.
func replayable(r *http.Request) bool {
	if r.Body != nil && r.Body != http.NoBody {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

func peekAll(br *bufio.Reader) []byte {
	n := br.Buffered()
	if n == 0 {
		return nil
	}
	b := make([]byte, n)
	_, _ = io.ReadFull(br, b)
	return b
}

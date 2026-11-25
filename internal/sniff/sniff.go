// Package sniff recovers the destination hostname from the first bytes of a
// transparently intercepted connection (TLS SNI or HTTP Host header), so that
// rules can match on names and proxies can resolve them remotely.
package sniff

import (
	"bytes"
	"net"
	"strings"
	"time"

	"oddlyproxifier/internal/netx"
)

const maxPeek = 8192

// Peek waits up to timeout for the client's first bytes and returns a
// connection that replays them, plus the hostname if one was found.
// Server-speaks-first protocols simply hit the timeout and yield "".
func Peek(c net.Conn, timeout time.Duration) (net.Conn, string) {
	buf := make([]byte, 0, 2048)
	host := ""
	deadline := time.Now().Add(timeout)
	for len(buf) < maxPeek {
		_ = c.SetReadDeadline(deadline)
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := c.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		var more bool
		host, more = Parse(buf)
		if err != nil || !more {
			break
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	return netx.WithPrefix(c, buf), host
}

// Parse inspects b. more reports that b looks like a known protocol but is
// still incomplete.
func Parse(b []byte) (host string, more bool) {
	if len(b) == 0 {
		return "", true
	}
	if b[0] == 0x16 {
		return parseTLS(b)
	}
	return parseHTTP(b)
}

func parseTLS(b []byte) (string, bool) {
	if len(b) < 5 {
		return "", true
	}
	if b[1] != 3 {
		return "", false
	}
	recLen := int(b[3])<<8 | int(b[4])
	if len(b) < 5+recLen {
		// A ClientHello may span records, but the SNI is practically always
		// inside the first one.
		if len(b) < maxPeek {
			return "", true
		}
		recLen = len(b) - 5
	}
	p := b[5 : 5+recLen]
	if len(p) < 4 || p[0] != 1 { // handshake type: client_hello
		return "", false
	}
	p = p[4:]
	// version(2) random(32)
	if len(p) < 34 {
		return "", false
	}
	p = p[34:]
	skip := func(lenBytes int) bool {
		if len(p) < lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(p[i])
		}
		if len(p) < lenBytes+n {
			return false
		}
		p = p[lenBytes+n:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return "", false
	}
	if len(p) < 2 {
		return "", false
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		typ := int(p[0])<<8 | int(p[1])
		l := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if l > len(p) {
			return "", false
		}
		if typ == 0 { // server_name
			d := p[:l]
			if len(d) < 5 || d[2] != 0 {
				return "", false
			}
			nl := int(d[3])<<8 | int(d[4])
			if 5+nl > len(d) {
				return "", false
			}
			return cleanHost(string(d[5 : 5+nl])), false
		}
		p = p[l:]
	}
	return "", false
}

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

func parseHTTP(b []byte) (string, bool) {
	isHTTP := false
	for _, m := range httpMethods {
		if len(b) >= len(m) {
			if string(b[:len(m)]) == m {
				isHTTP = true
				break
			}
		} else if strings.HasPrefix(m, string(b)) {
			return "", true // could still become a method
		}
	}
	if !isHTTP {
		return "", false
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	head := b
	if end >= 0 {
		head = b[:end]
	}
	lines := bytes.Split(head, []byte("\r\n"))
	if end < 0 {
		// The last line is not finished yet: a name could be cut in half.
		lines = lines[:len(lines)-1]
	}
	for i := 1; i < len(lines); i++ {
		if line := lines[i]; len(line) > 5 && strings.EqualFold(string(line[:5]), "host:") {
			return cleanHost(strings.TrimSpace(string(line[5:]))), false
		}
	}
	return "", end < 0
}

// cleanHost strips a port and rejects anything that is not a plausible name.
func cleanHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "" || len(h) > 253 {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == ':'
		if !ok {
			return ""
		}
	}
	return h
}

// Tap returns a connection that inspects the first bytes read from c while
// they flow by and reports the hostname through found, without delaying the
// stream. found is called at most once, from the reading goroutine.
func Tap(c net.Conn, found func(host string)) net.Conn {
	return &tapConn{Conn: c, found: found}
}

type tapConn struct {
	net.Conn
	found func(string)
	buf   []byte
	done  bool
}

func (t *tapConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if !t.done && n > 0 {
		t.buf = append(t.buf, b[:n]...)
		host, more := Parse(t.buf)
		if host != "" || !more || len(t.buf) >= maxPeek {
			t.done, t.buf = true, nil
			if host != "" {
				t.found(host)
			}
		}
	}
	return n, err
}

func (t *tapConn) CloseWrite() error { return netx.CloseWrite(t.Conn) }

// NetConn exposes the wrapped connection.
func (t *tapConn) NetConn() net.Conn { return t.Conn }

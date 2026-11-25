package sniff

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"oddlyproxifier/internal/proxytest"
)

// clientHello returns the bytes a real TLS client sends first.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(b, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func TestParseTLS(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	host, more := Parse(hello)
	if host != "www.example.com" || more {
		t.Fatalf("Parse(ClientHello) = %q, %v", host, more)
	}
	// Every incomplete prefix asks for more instead of guessing.
	for n := 0; n < len(hello); n++ {
		if host, more := Parse(hello[:n]); host != "" || !more {
			t.Fatalf("Parse(first %d of %d bytes) = %q, %v; want \"\", true", n, len(hello), host, more)
		}
	}
	// Bytes after the record do not matter.
	if host, _ := Parse(append(append([]byte{}, hello...), 1, 2, 3)); host != "www.example.com" {
		t.Errorf("trailing bytes confused the parser: %q", host)
	}
}

func TestParseTLSWithoutSNI(t *testing.T) {
	// crypto/tls sends no server_name extension for IP literals.
	hello := clientHello(t, "192.0.2.1")
	if host, more := Parse(hello); host != "" || more {
		t.Errorf("Parse = %q, %v; want \"\", false", host, more)
	}
}

func TestParseTLSGarbage(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	// Truncating fields inside the record must never panic.
	for cut := 6; cut < len(hello); cut++ {
		b := append([]byte{}, hello[:cut]...)
		b[3], b[4] = byte((cut-5)>>8), byte(cut-5) // pretend the record ends here
		Parse(b)
	}
	for _, b := range [][]byte{
		{0x16, 3, 1, 0, 0},
		{0x16, 2, 0, 0, 5, 1, 2, 3, 4, 5},
		{0x16, 3, 1, 0, 4, 2, 0, 0, 0}, // server_hello
	} {
		if host, more := Parse(b); host != "" || more {
			t.Errorf("Parse(%v) = %q, %v", b, host, more)
		}
	}
}

func TestParseHTTP(t *testing.T) {
	cases := []struct {
		in   string
		host string
		more bool
	}{
		{"GET / HTTP/1.1\r\nHost: Example.com\r\n\r\n", "example.com", false},
		{"GET / HTTP/1.1\r\nUser-Agent: x\r\nhost:example.com:8080\r\n\r\nbody", "example.com", false},
		{"POST /x HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n", "2001:db8::1", false},
		{"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "example.com", false},
		{"GET / HTTP/1.1\r\nHost: exam", "", true}, // a name cut in half is not a name yet
		{"GET / HTTP/1.1\r\nHost: example.com\r\n", "example.com", false},
		{"GET / HTTP/1.1\r\nHost: example.com\r", "", true},
		{"GET / HTTP/1.1", "", true},
		{"GET / HTTP/1.0\r\n\r\n", "", false},
		{"GET / HTTP/1.1\r\nUser-Agent: x\r\n", "", true},
		{"G", "", true},
		{"GE", "", true},
		{"PO", "", true},
		{"", "", true},
		{"SSH-2.0-OpenSSH_9.6\r\n", "", false},
		{"\x05\x01\x00", "", false},
		{"GETX / HTTP/1.1\r\nHost: a.example\r\n\r\n", "", false},
		{"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n", "", false},
		{"GET / HTTP/1.1\r\nHost: " + strings.Repeat("a", 300) + "\r\n\r\n", "", false},
	}
	for _, c := range cases {
		host, more := Parse([]byte(c.in))
		if host != c.host || more != c.more {
			t.Errorf("Parse(%q) = %q, %v; want %q, %v", c.in, host, more, c.host, c.more)
		}
	}
}

// accept returns the server end of the next connection to a fresh listener.
func accept(t *testing.T) (addr string, conn func() net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), func() net.Conn {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

// Peek must hand back every byte: the TLS handshake still completes on the
// peeked connection.
func TestPeekThenFullHandshake(t *testing.T) {
	cert, err := proxytest.SelfSigned("peek.example")
	if err != nil {
		t.Fatal(err)
	}
	addr, next := accept(t)

	errc := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "peek.example", InsecureSkipVerify: true})
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		if _, err := c.Write([]byte("ping")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(c, buf)
		if err == nil && string(buf) != "pong" {
			err = io.ErrUnexpectedEOF
		}
		errc <- err
	}()

	peeked, host := Peek(next(), 2*time.Second)
	if host != "peek.example" {
		t.Fatalf("Peek found %q", host)
	}
	srv := tls.Server(peeked, &tls.Config{Certificates: []tls.Certificate{cert}})
	buf := make([]byte, 4)
	if _, err := io.ReadFull(srv, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("server read %q, %v", buf, err)
	}
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("client: %v", err)
	}
}

func TestPeekHTTPInPieces(t *testing.T) {
	addr, next := accept(t)
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer c.Close()
		for _, part := range []string{"GET / HT", "TP/1.1\r\nHo", "st: pie", "ces.example\r\n\r\n"} {
			_, _ = c.Write([]byte(part))
			time.Sleep(30 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
	}()
	peeked, host := Peek(next(), 2*time.Second)
	if host != "pieces.example" {
		t.Fatalf("Peek found %q", host)
	}
	want := "GET / HTTP/1.1\r\nHost: pieces.example\r\n\r\n"
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(peeked, buf); err != nil || string(buf) != want {
		t.Errorf("replayed %q, %v", buf, err)
	}
}

// A protocol where the server talks first: Peek gives up after the timeout
// and leaves a usable connection behind.
func TestPeekTimeout(t *testing.T) {
	addr, next := accept(t)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	start := time.Now()
	peeked, host := Peek(next(), 150*time.Millisecond)
	if d := time.Since(start); host != "" || d < 100*time.Millisecond || d > 2*time.Second {
		t.Fatalf("Peek returned %q after %v", host, d)
	}
	if _, err := peeked.Write([]byte("220 hello\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("EHLO x\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_ = peeked.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(peeked, buf); err != nil || string(buf) != "EHLO x\r\n" {
		t.Errorf("read after the timeout: %q, %v", buf, err)
	}
}

func TestPeekStopsAtUnknownProtocol(t *testing.T) {
	addr, next := accept(t)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("\x00\x01binary")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	peeked, host := Peek(next(), 3*time.Second)
	if host != "" || time.Since(start) > 2*time.Second {
		t.Fatalf("Peek waited %v on bytes that are neither TLS nor HTTP (host %q)", time.Since(start), host)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(peeked, buf); err != nil || string(buf) != "\x00\x01binary" {
		t.Errorf("replayed %q, %v", buf, err)
	}
}

func TestTap(t *testing.T) {
	hello := clientHello(t, "tap.example")
	addr, next := accept(t)
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer c.Close()
		// In two pieces, so that the name only shows up on the second read.
		_, _ = c.Write(hello[:20])
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(hello[20:])
		_, _ = c.Write([]byte("and more"))
	}()

	var found []string
	tap := Tap(next(), func(h string) { found = append(found, h) })
	got, err := io.ReadAll(tap)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(append([]byte{}, hello...), "and more"...); !bytes.Equal(got, want) {
		t.Errorf("the tap changed the stream: %d bytes, want %d", len(got), len(want))
	}
	if len(found) != 1 || found[0] != "tap.example" {
		t.Errorf("found = %q, want exactly one report", found)
	}
}

func TestTapGivesUpQuietly(t *testing.T) {
	addr, next := accept(t)
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(bytes.Repeat([]byte{0xAB}, 3*maxPeek))
	}()
	tap := Tap(next(), func(h string) { t.Errorf("unexpected host %q", h) })
	n, err := io.Copy(io.Discard, tap)
	if err != nil || n != 3*maxPeek {
		t.Errorf("copied %d bytes, %v", n, err)
	}
	if tc := tap.(*tapConn); !tc.done || tc.buf != nil {
		t.Error("the tap keeps buffering after it gave up")
	}
}

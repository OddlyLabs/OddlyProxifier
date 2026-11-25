package netx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// pair returns the two ends of a TCP connection over loopback.
func pair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { c.Close(); r.c.Close() })
	return c.(*net.TCPConn), r.c.(*net.TCPConn)
}

func TestWithPrefix(t *testing.T) {
	c, s := pair(t)
	if WithPrefix(c, nil) != net.Conn(c) {
		t.Error("an empty prefix should return the connection itself")
	}
	go func() {
		_, _ = s.Write([]byte(" world"))
		_ = s.CloseWrite()
	}()
	p := WithPrefix(c, []byte("hello"))
	small := make([]byte, 2)
	if n, _ := p.Read(small); string(small[:n]) != "he" {
		t.Fatalf("first read = %q", small[:n])
	}
	rest, err := io.ReadAll(p)
	if err != nil || string(rest) != "llo world" {
		t.Fatalf("rest = %q, %v", rest, err)
	}
	if pc, ok := p.(*PrefixConn); !ok || pc.NetConn() != net.Conn(c) {
		t.Error("NetConn does not expose the wrapped connection")
	}
}

// relayed sets up client <-> relay <-> server and returns the outer ends.
func relayed(t *testing.T, idle time.Duration) (client, server *net.TCPConn, up, down *atomic.Int64, done chan struct{}) {
	t.Helper()
	client, a := pair(t)
	b, server := pair(t)
	up, down = new(atomic.Int64), new(atomic.Int64)
	done = make(chan struct{})
	go func() {
		Relay(a, b, up, down, idle)
		_ = a.Close()
		_ = b.Close()
		close(done)
	}()
	return client, server, up, down, done
}

func wait(t *testing.T, done chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestRelayHalfClose(t *testing.T) {
	client, server, up, down, done := relayed(t, 0)

	request := bytes.Repeat([]byte("request "), 20000) // larger than one buffer
	go func() {
		_, _ = client.Write(request)
		_ = client.CloseWrite() // "I am done sending", like HTTP/1.0 clients do
	}()
	got, err := io.ReadAll(server)
	if err != nil || !bytes.Equal(got, request) {
		t.Fatalf("server got %d bytes, err %v; want %d", len(got), err, len(request))
	}
	// The other direction must still work after the half-close.
	if _, err := server.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	reply, err := io.ReadAll(client)
	if err != nil || string(reply) != "response" {
		t.Fatalf("client got %q, %v", reply, err)
	}
	wait(t, done, "the relay to end")
	if up.Load() != int64(len(request)) || down.Load() != int64(len("response")) {
		t.Errorf("counters: up %d down %d, want %d and %d", up.Load(), down.Load(), len(request), len("response"))
	}
}

func TestRelayEndsWhenOneSideResets(t *testing.T) {
	client, server, _, _, done := relayed(t, 0)
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	Reset(server)
	wait(t, done, "the relay to end after a reset")
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(buf); err == nil {
		t.Error("the client can still read after the server reset the connection")
	}
}

func TestRelayIdleTimeout(t *testing.T) {
	_, _, _, _, done := relayed(t, 150*time.Millisecond)
	start := time.Now()
	wait(t, done, "the idle timeout")
	if d := time.Since(start); d < 100*time.Millisecond {
		t.Errorf("gave up after %v, before the idle time was over", d)
	}
}

func TestRelayIdleTimeoutSparesBusyConnections(t *testing.T) {
	client, server, _, down, done := relayed(t, 200*time.Millisecond)
	// Only the server talks; the silent client direction must not kill it.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(40 * time.Millisecond):
				_, _ = server.Write([]byte("tick"))
			}
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, client) }()
	select {
	case <-done:
		t.Fatal("the relay ended although one direction was busy")
	case <-time.After(700 * time.Millisecond):
	}
	close(stop)
	wait(t, done, "the idle timeout after traffic stopped")
	if down.Load() == 0 {
		t.Error("no bytes were counted")
	}
}

func TestResetIsAbortive(t *testing.T) {
	c, s := pair(t)
	Reset(WithPrefix(s, []byte("x"))) // must unwrap down to the socket
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Read(make([]byte, 1))
	if err == nil || errors.Is(err, io.EOF) {
		t.Errorf("read after Reset: %v, want a connection reset error", err)
	}
}

func TestCloseWriteOnPlainConn(t *testing.T) {
	a, b := net.Pipe() // has no CloseWrite
	defer a.Close()
	defer b.Close()
	if err := CloseWrite(a); err != nil {
		t.Errorf("CloseWrite on a connection without half-close: %v", err)
	}
}

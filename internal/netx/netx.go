// Package netx holds small connection helpers shared by the engine.
package netx

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PrefixConn replays already-consumed bytes before reading from the socket.
type PrefixConn struct {
	net.Conn
	pre []byte
}

// WithPrefix returns c unchanged when there is nothing to replay.
func WithPrefix(c net.Conn, pre []byte) net.Conn {
	if len(pre) == 0 {
		return c
	}
	return &PrefixConn{Conn: c, pre: pre}
}

func (p *PrefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *PrefixConn) CloseWrite() error { return CloseWrite(p.Conn) }

// NetConn exposes the wrapped connection.
func (p *PrefixConn) NetConn() net.Conn { return p.Conn }

// CloseWrite half-closes c when the underlying type supports it.
func CloseWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Reset closes c abortively (TCP RST), so that the peer sees a refused or
// reset connection rather than a clean end of stream.
func Reset(c net.Conn) {
	inner := c
	for {
		if tc, ok := inner.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
			break
		}
		u, ok := inner.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		inner = u.NetConn()
	}
	_ = c.Close()
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// Relay copies both directions until both sides are done. up counts bytes
// a->b, down counts b->a. With idle > 0 the connection is torn down once
// neither direction has seen traffic for that long; idle <= 0 never times
// out, which is what a transparent proxy should do by default.
func Relay(a, b net.Conn, up, down *atomic.Int64, idle time.Duration) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())

	cp := func(dst, src net.Conn, n *atomic.Int64) {
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		buf := *bp
		for {
			if idle > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idle))
			}
			nr, err := src.Read(buf)
			if nr > 0 {
				last.Store(time.Now().UnixNano())
				n.Add(int64(nr))
				if _, werr := dst.Write(buf[:nr]); werr != nil {
					_ = src.Close()
					_ = dst.Close()
					return
				}
			}
			if err == nil {
				continue
			}
			var ne net.Error
			if idle > 0 && errors.As(err, &ne) && ne.Timeout() &&
				time.Since(time.Unix(0, last.Load())) < idle {
				continue // the other direction is still busy
			}
			if errors.Is(err, io.EOF) {
				_ = CloseWrite(dst) // let the other direction drain
			} else {
				_ = src.Close()
				_ = dst.Close()
			}
			return
		}
	}

	done := make(chan struct{})
	go func() { cp(b, a, up); close(done) }()
	cp(a, b, down)
	<-done
}

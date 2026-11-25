// Package proxytest provides small proxy servers of every type the engine
// can use as an upstream, plus an echo server to tunnel to. They back the
// tests and the tools/testproxy program and are not meant for production.
package proxytest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/netx"
)

// Options configures a Server.
type Options struct {
	// Type is one of config.TypeSOCKS5, TypeSOCKS4, TypeSOCKS4A, TypeHTTP and
	// TypeHTTPS. A SOCKS4 server refuses SOCKS4a requests, like the real thing.
	Type string
	// Listen defaults to "127.0.0.1:0".
	Listen string
	// User switches authentication on. SOCKS4 only compares the user id.
	User, Pass string
	// Dial opens the outbound connection; the default dials the requested
	// address as it is.
	Dial func(network, addr string) (net.Conn, error)
	// Cert is the certificate of an HTTPS proxy; the default is a fresh
	// self-signed one for localhost and 127.0.0.1.
	Cert *tls.Certificate
	// A SOCKS5 server relays UDP (UDP ASSOCIATE) unless NoUDP is set; it then
	// answers the request with "command not supported".
	NoUDP bool
	// UDPAnyAddr makes the server report 0.0.0.0 as the address of its UDP
	// relay, the way servers do that listen on every address.
	UDPAnyAddr bool
	// UDPReplyName makes relayed replies carry the destination as the client
	// named it instead of the address they came from.
	UDPReplyName bool
	// Logf, when set, receives one line per request.
	Logf func(format string, args ...any)
}

// Server is a running proxy server.
type Server struct {
	opt Options
	ln  net.Listener
	wg  sync.WaitGroup

	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	targets    []string
	accepted   int
	closed     bool
	udpTargets []string
	assocs     int                   // UDP associations so far
	live       map[net.Conn]struct{} // connections of the open ones
}

// Start opens the listener and serves in the background.
func Start(o Options) (*Server, error) {
	switch o.Type {
	case config.TypeSOCKS5, config.TypeSOCKS4, config.TypeSOCKS4A, config.TypeHTTP, config.TypeHTTPS:
	default:
		return nil, fmt.Errorf("unknown proxy type %q", o.Type)
	}
	if o.Listen == "" {
		o.Listen = "127.0.0.1:0"
	}
	if o.Dial == nil {
		o.Dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 10*time.Second)
		}
	}
	ln, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return nil, err
	}
	if o.Type == config.TypeHTTPS {
		cert := o.Cert
		if cert == nil {
			c, err := SelfSigned("localhost")
			if err != nil {
				_ = ln.Close()
				return nil, err
			}
			cert = &c
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*cert}})
	}
	s := &Server{opt: o, ln: ln, conns: map[net.Conn]struct{}{}, live: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// SelfSigned makes a certificate for the given DNS name and the loopback
// addresses.
func SelfSigned(name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{name},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// Addr is the listening address as host:port.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Port is the listening port.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Config describes the server as a profile entry. The id doubles as name.
func (s *Server) Config(id string) config.Proxy {
	host, _, _ := net.SplitHostPort(s.Addr())
	return config.Proxy{
		ID: id, Name: id, Type: s.opt.Type, Host: host, Port: s.Port(),
		Username: s.opt.User, Password: s.opt.Pass,
		TLSInsecure: s.opt.Type == config.TypeHTTPS,
	}
}

// Targets lists the destinations clients asked for, oldest first, exactly as
// they were requested (names are not resolved).
func (s *Server) Targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

// Accepted is the number of client connections so far.
func (s *Server) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// Reset forgets the recorded targets and the counts of connections and UDP
// associations.
func (s *Server) Reset() {
	s.mu.Lock()
	s.targets, s.accepted = nil, 0
	s.udpTargets, s.assocs = nil, 0
	s.mu.Unlock()
}

// Close stops the server and drops every connection.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	_ = s.ln.Close()
	s.wg.Wait()
}

func (s *Server) logf(format string, args ...any) {
	if s.opt.Logf != nil {
		s.opt.Logf(format, args...)
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	_ = c.Close()
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if !s.track(c) {
			return
		}
		s.mu.Lock()
		s.accepted++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			s.serve(c)
		}()
	}
}

// handshake is the outcome of the protocol-specific part.
type handshake struct {
	client net.Conn          // the client side of the tunnel
	target string            // host:port
	reply  func(error) error // tells the client how the dial went
	udp    bool              // not a tunnel: the client asks for a UDP association
}

func (s *Server) serve(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	var (
		h   handshake
		err error
	)
	switch s.opt.Type {
	case config.TypeSOCKS5:
		h, err = s.socks5(c)
	case config.TypeSOCKS4, config.TypeSOCKS4A:
		h, err = s.socks4(c)
	default:
		h, err = s.httpConnect(c)
	}
	from := c.RemoteAddr()
	if err != nil {
		s.logf("%s %s: refused: %v", s.opt.Type, from, err)
		return
	}
	if h.udp {
		s.associate(c)
		return
	}
	s.mu.Lock()
	s.targets = append(s.targets, h.target)
	s.mu.Unlock()

	remote, err := s.opt.Dial("tcp", h.target)
	if err != nil {
		s.logf("%s %s -> %s: %v", s.opt.Type, from, h.target, err)
		_ = h.reply(err)
		return
	}
	if !s.track(remote) {
		return
	}
	defer s.untrack(remote)
	if err := h.reply(nil); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	var up, down atomic.Int64
	netx.Relay(h.client, remote, &up, &down, 0)
	s.logf("%s %s -> %s: closed, %d bytes up, %d bytes down", s.opt.Type, from, h.target, up.Load(), down.Load())
}

// ---------------------------------------------------------------- SOCKS5

func (s *Server) socks5(c net.Conn) (handshake, error) {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return handshake{}, err
	}
	if h[0] != 5 {
		return handshake{}, fmt.Errorf("not SOCKS5 (first byte 0x%02X)", h[0])
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return handshake{}, err
	}
	want := byte(0)
	if s.opt.User != "" {
		want = 2
	}
	if !bytes.Contains(methods, []byte{want}) {
		_, _ = c.Write([]byte{5, 0xFF})
		return handshake{}, fmt.Errorf("client offers methods %v, server wants %d", methods, want)
	}
	if _, err := c.Write([]byte{5, want}); err != nil {
		return handshake{}, err
	}
	if want == 2 { // RFC 1929
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return handshake{}, err
		}
		user := make([]byte, h[1])
		if _, err := io.ReadFull(c, user); err != nil {
			return handshake{}, err
		}
		if _, err := io.ReadFull(c, h[:1]); err != nil {
			return handshake{}, err
		}
		pass := make([]byte, h[0])
		if _, err := io.ReadFull(c, pass); err != nil {
			return handshake{}, err
		}
		if string(user) != s.opt.User || string(pass) != s.opt.Pass {
			_, _ = c.Write([]byte{1, 1})
			return handshake{}, fmt.Errorf("wrong credentials for user %q", user)
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return handshake{}, err
		}
	}
	var q [4]byte
	if _, err := io.ReadFull(c, q[:]); err != nil {
		return handshake{}, err
	}
	var host string
	switch q[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return handshake{}, err
		}
		host = netip.AddrFrom4(a).String()
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return handshake{}, err
		}
		host = netip.AddrFrom16(a).String()
	case 3:
		if _, err := io.ReadFull(c, h[:1]); err != nil {
			return handshake{}, err
		}
		name := make([]byte, h[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return handshake{}, err
		}
		host = string(name)
	default:
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return handshake{}, fmt.Errorf("address type %d", q[3])
	}
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return handshake{}, err
	}
	if q[1] == 3 && !s.opt.NoUDP {
		// The address in the request is where the client means to send from.
		// Hardly any client knows it; the first datagram tells.
		return handshake{udp: true}, nil
	}
	if q[1] != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return handshake{}, fmt.Errorf("command %d", q[1])
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(h[:]))))
	return handshake{client: c, target: target, reply: func(err error) error {
		code := byte(0)
		if err != nil {
			code = 5 // connection refused
			var de *net.DNSError
			if errors.As(err, &de) {
				code = 4 // host unreachable
			}
		}
		_, werr := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		return werr
	}}, nil
}

// ---------------------------------------------------------------- SOCKS4

func readCString(r io.Reader) (string, error) {
	var out []byte
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(out), nil
		}
		if len(out) >= 255 {
			return "", errors.New("string too long")
		}
		out = append(out, b[0])
	}
}

func (s *Server) socks4(c net.Conn) (handshake, error) {
	var h [8]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return handshake{}, err
	}
	if h[0] != 4 {
		return handshake{}, fmt.Errorf("not SOCKS4 (first byte 0x%02X)", h[0])
	}
	user, err := readCString(c)
	if err != nil {
		return handshake{}, err
	}
	refuse := func(code byte, why string) (handshake, error) {
		_, _ = c.Write([]byte{0, code, 0, 0, 0, 0, 0, 0})
		return handshake{}, errors.New(why)
	}
	host := netip.AddrFrom4([4]byte(h[4:8])).String()
	if h[4] == 0 && h[5] == 0 && h[6] == 0 && h[7] != 0 {
		name, err := readCString(c)
		if err != nil {
			return handshake{}, err
		}
		if s.opt.Type != config.TypeSOCKS4A {
			return refuse(0x5B, "SOCKS4a request, but this is a plain SOCKS4 server")
		}
		host = name
	}
	if h[1] != 1 {
		return refuse(0x5B, fmt.Sprintf("command %d", h[1]))
	}
	if s.opt.User != "" && user != s.opt.User {
		return refuse(0x5D, fmt.Sprintf("wrong user id %q", user))
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(h[2:4]))))
	return handshake{client: c, target: target, reply: func(err error) error {
		code := byte(0x5A)
		if err != nil {
			code = 0x5B
		}
		_, werr := c.Write([]byte{0, code, 0, 0, 0, 0, 0, 0})
		return werr
	}}, nil
}

// ------------------------------------------------------------ HTTP CONNECT

func (s *Server) httpConnect(c net.Conn) (handshake, error) {
	br := bufio.NewReader(c)
	r, err := http.ReadRequest(br)
	if err != nil {
		return handshake{}, err
	}
	respond := func(status string, headers ...string) {
		var b strings.Builder
		fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", status)
		for _, h := range headers {
			b.WriteString(h + "\r\n")
		}
		b.WriteString("Content-Length: 0\r\n\r\n")
		_, _ = io.WriteString(c, b.String())
	}
	if r.Method != http.MethodConnect {
		respond("405 Method Not Allowed", "Allow: CONNECT")
		return handshake{}, fmt.Errorf("method %s", r.Method)
	}
	if s.opt.User != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.opt.User+":"+s.opt.Pass))
		if r.Header.Get("Proxy-Authorization") != want {
			respond("407 Proxy Authentication Required", `Proxy-Authenticate: Basic realm="proxytest"`)
			return handshake{}, errors.New("wrong or missing credentials")
		}
	}
	client := c
	if n := br.Buffered(); n > 0 {
		pre := make([]byte, n)
		_, _ = io.ReadFull(br, pre)
		client = netx.WithPrefix(c, pre)
	}
	return handshake{client: client, target: r.RequestURI, reply: func(err error) error {
		if err != nil {
			respond("502 Bad Gateway")
			return nil
		}
		_, werr := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		return werr
	}}, nil
}

// ------------------------------------------------------------------ helpers

// Mapper returns a Dial function for Options that sends the listed
// "host:port" targets to other addresses. Every other target under the
// reserved .test and .invalid domains is refused at once, so that tests
// never depend on a real resolver; anything else is dialed as it is.
func Mapper(m map[string]string) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		if to, ok := m[addr]; ok {
			return net.DialTimeout(network, to, 10*time.Second)
		}
		if host, _, err := net.SplitHostPort(addr); err == nil {
			if strings.HasSuffix(host, ".test") || strings.HasSuffix(host, ".invalid") {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
		}
		return net.DialTimeout(network, addr, 10*time.Second)
	}
}

// Echo is a TCP server that sends back whatever it receives.
type Echo struct {
	ln net.Listener
	wg sync.WaitGroup

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	accepted int
}

// StartEcho serves on a free loopback port. A non-empty banner is sent to
// every client first, the way SMTP or SSH servers greet.
func StartEcho(banner string) (*Echo, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	e := &Echo{ln: ln, conns: map[net.Conn]struct{}{}}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.conns[c] = struct{}{}
			e.accepted++
			e.mu.Unlock()
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				defer func() {
					e.mu.Lock()
					delete(e.conns, c)
					e.mu.Unlock()
					_ = c.Close()
				}()
				if banner != "" {
					if _, err := io.WriteString(c, banner); err != nil {
						return
					}
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return e, nil
}

// Addr is the listening address as host:port.
func (e *Echo) Addr() string { return e.ln.Addr().String() }

// Port is the listening port.
func (e *Echo) Port() int { return e.ln.Addr().(*net.TCPAddr).Port }

// Accepted is the number of client connections so far.
func (e *Echo) Accepted() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.accepted
}

// Close stops the server and drops every connection.
func (e *Echo) Close() {
	_ = e.ln.Close()
	e.mu.Lock()
	for c := range e.conns {
		_ = c.Close()
	}
	e.mu.Unlock()
	e.wg.Wait()
}

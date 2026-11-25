// Package proxy implements the client side of SOCKS4/4a/5 and HTTP(S)
// CONNECT, and the chaining of several such hops.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
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

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/netx"
)

// DialFunc opens the very first TCP connection of a chain.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ErrTarget marks failures where the proxy itself worked but could not (or
// would not) reach the requested destination.
var ErrTarget = errors.New("target unreachable through proxy")

// Hop is one proxy server.
type Hop struct {
	cfg config.Proxy

	// LookupIPv4 resolves names where the protocol cannot carry them (plain
	// SOCKS4). nil means the system resolver.
	LookupIPv4 func(ctx context.Context, host string) (netip.Addr, error)
}

func NewHop(p config.Proxy) *Hop { return &Hop{cfg: p} }

func (h *Hop) ID() string   { return h.cfg.ID }
func (h *Hop) Type() string { return h.cfg.Type }
func (h *Hop) Name() string { return h.cfg.Name }
func (h *Hop) Addr() string { return net.JoinHostPort(h.cfg.Host, strconv.Itoa(h.cfg.Port)) }
func (h *Hop) Host() string { return h.cfg.Host }
func (h *Hop) Port() int    { return h.cfg.Port }

// Handshake asks the proxy reachable over c to connect to host:port and
// returns the tunnel (which may wrap c, e.g. in TLS).
func (h *Hop) Handshake(ctx context.Context, c net.Conn, host string, port int) (net.Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	var out net.Conn = c
	var err error
	switch h.cfg.Type {
	case config.TypeSOCKS5:
		err = socks5(c, h.cfg.Username, h.cfg.Password, host, port)
	case config.TypeSOCKS4, config.TypeSOCKS4A:
		err = socks4(ctx, c, h.LookupIPv4, h.cfg.Type == config.TypeSOCKS4A, h.cfg.Username, host, port)
	case config.TypeHTTPS:
		name := h.cfg.TLSServerName
		if name == "" {
			name = h.cfg.Host
		}
		tc := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: h.cfg.TLSInsecure})
		if err = tc.HandshakeContext(ctx); err != nil {
			err = fmt.Errorf("tls: %w", err)
			break
		}
		out, err = httpConnect(tc, h.cfg.Username, h.cfg.Password, host, port)
	case config.TypeHTTP:
		out, err = httpConnect(c, h.cfg.Username, h.cfg.Password, host, port)
	default:
		err = fmt.Errorf("unknown proxy type %q", h.cfg.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s (%s): %w", h.cfg.Name, h.cfg.Type, err)
	}
	_ = out.SetDeadline(time.Time{})
	return out, nil
}

// DialChain connects through hops in order and finally to host:port.
func DialChain(ctx context.Context, base DialFunc, hops []*Hop, host string, port int) (net.Conn, error) {
	if len(hops) == 0 {
		return nil, errors.New("empty proxy chain")
	}
	c, err := base(ctx, "tcp", hops[0].Addr())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", hops[0].Name(), err)
	}
	for i, h := range hops {
		nh, np := host, port
		last := i+1 == len(hops)
		if !last {
			nh, np = hops[i+1].Host(), hops[i+1].Port()
		}
		next, err := h.Handshake(ctx, c, nh, np)
		if err != nil {
			_ = c.Close()
			if !last && errors.Is(err, ErrTarget) {
				// What this hop could not reach is the next proxy, not the
				// destination: the chain is broken, the target is not to blame.
				return nil, fmt.Errorf("cannot reach proxy %s: %v", hops[i+1].Name(), err)
			}
			return nil, err
		}
		c = next
	}
	return c, nil
}

// Check measures how long it takes to open a tunnel to target through hops.
// For port-80 targets it also verifies that an HTTP response comes back.
func Check(ctx context.Context, base DialFunc, hops []*Hop, target string) (time.Duration, error) {
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	c, err := DialChain(ctx, base, hops, host, port)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if port == 80 {
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		if _, err := fmt.Fprintf(c, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
			return 0, err
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil {
			return 0, fmt.Errorf("no response through tunnel: %w", err)
		}
		if string(buf) != "HTTP/" {
			return 0, errors.New("unexpected response through tunnel")
		}
	}
	return time.Since(start), nil
}

// ---------------------------------------------------------------- SOCKS5

var socks5Errors = map[byte]string{
	1: "general failure", 2: "connection not allowed by ruleset", 3: "network unreachable",
	4: "host unreachable", 5: "connection refused", 6: "TTL expired",
	7: "command not supported", 8: "address type not supported",
}

func socks5(c net.Conn, user, pass, host string, port int) error {
	_, _, err := socks5Request(c, user, pass, 1, host, port)
	return err
}

// socks5Request signs in and sends one request: cmd 1 connects to host:port,
// cmd 3 opens a UDP association. It returns the address the proxy reports as
// bound, which matters for associations only.
func socks5Request(c net.Conn, user, pass string, cmd byte, host string, port int) (string, int, error) {
	// Whatever is wrong with the request is found before the first byte goes
	// out, not after a round trip to the proxy.
	if len(user) > 255 || len(pass) > 255 {
		return "", 0, errors.New("user name or password longer than 255 bytes")
	}
	req := []byte{5, cmd, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			req = append(req, 1)
		} else {
			req = append(req, 4)
		}
		req = append(req, ip.AsSlice()...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return "", 0, errors.New("bad hostname length")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))

	hello := []byte{5, 1, 0}
	if user != "" {
		hello = []byte{5, 2, 0, 2}
	}
	if _, err := c.Write(hello); err != nil {
		return "", 0, err
	}
	var r [4]byte
	if _, err := io.ReadFull(c, r[:2]); err != nil {
		return "", 0, err
	}
	if r[0] != 5 {
		return "", 0, errors.New("not a SOCKS5 server")
	}
	switch r[1] {
	case 0:
	case 2:
		if user == "" {
			return "", 0, errors.New("server requires authentication")
		}
		auth := make([]byte, 0, 3+len(user)+len(pass))
		auth = append(auth, 1, byte(len(user)))
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := c.Write(auth); err != nil {
			return "", 0, err
		}
		if _, err := io.ReadFull(c, r[:2]); err != nil {
			return "", 0, err
		}
		if r[1] != 0 {
			return "", 0, errors.New("authentication failed")
		}
	default:
		return "", 0, errors.New("no acceptable authentication method")
	}

	if _, err := c.Write(req); err != nil {
		return "", 0, err
	}
	if _, err := io.ReadFull(c, r[:4]); err != nil {
		return "", 0, err
	}
	if r[1] != 0 {
		msg, ok := socks5Errors[r[1]]
		if !ok {
			return "", 0, fmt.Errorf("reply code %d", r[1])
		}
		if cmd == 1 && (r[1] >= 2 && r[1] <= 6 || r[1] == 8) {
			return "", 0, fmt.Errorf("%w: %s", ErrTarget, msg)
		}
		if cmd == 3 && (r[1] == 2 || r[1] == 7) {
			// The proxy's answer to the question whether it relays UDP.
			return "", 0, fmt.Errorf("%w: %s", ErrNoUDP, msg)
		}
		return "", 0, errors.New(msg)
	}
	var bound string
	switch r[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return "", 0, err
		}
		bound = netip.AddrFrom4(a).String()
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return "", 0, err
		}
		bound = netip.AddrFrom16(a).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", 0, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", 0, err
		}
		bound = string(name)
	default:
		return "", 0, errors.New("bad address type in reply")
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return "", 0, err
	}
	return bound, int(binary.BigEndian.Uint16(pb[:])), nil
}

// ---------------------------------------------------------------- SOCKS4

func socks4(ctx context.Context, c net.Conn, lookup func(context.Context, string) (netip.Addr, error), fourA bool, user, host string, port int) error {
	if lookup == nil {
		lookup = func(ctx context.Context, host string) (netip.Addr, error) {
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if err != nil {
				return netip.Addr{}, err
			}
			if len(ips) == 0 {
				return netip.Addr{}, errors.New("no IPv4 address")
			}
			return ips[0], nil
		}
	}
	req := []byte{4, 1}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	ip, err := netip.ParseAddr(host)
	domain := ""
	switch {
	case err == nil:
		ip = ip.Unmap()
	case fourA:
		ip, domain = netip.AddrFrom4([4]byte{0, 0, 0, 1}), host
	default:
		a, lerr := lookup(ctx, host)
		if lerr != nil {
			return fmt.Errorf("%w: resolve %s: %v", ErrTarget, host, lerr)
		}
		ip = a.Unmap()
	}
	if !ip.Is4() {
		return fmt.Errorf("%w: SOCKS4 does not support IPv6 targets", ErrTarget)
	}
	req = append(req, ip.AsSlice()...)
	req = append(req, user...)
	req = append(req, 0)
	if domain != "" {
		req = append(req, domain...)
		req = append(req, 0)
	}
	if _, err := c.Write(req); err != nil {
		return err
	}
	var r [8]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return err
	}
	switch r[1] {
	case 0x5A:
		return nil
	case 0x5B:
		return fmt.Errorf("%w: request rejected or failed", ErrTarget)
	default:
		return fmt.Errorf("request rejected (code 0x%02X)", r[1])
	}
}

// ------------------------------------------------------------ HTTP CONNECT

func httpConnect(c net.Conn, user, pass, host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", target, target)
	if user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusProxyAuthRequired:
			return nil, errors.New("proxy authentication required")
		case http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway,
			http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return nil, fmt.Errorf("%w: CONNECT refused: %s", ErrTarget, resp.Status)
		}
		return nil, fmt.Errorf("CONNECT refused: %s", resp.Status)
	}
	// Bytes the server sent right after the header already belong to the tunnel.
	if n := br.Buffered(); n > 0 {
		pre := make([]byte, n)
		_, _ = io.ReadFull(br, pre)
		return netx.WithPrefix(c, pre), nil
	}
	return c, nil
}

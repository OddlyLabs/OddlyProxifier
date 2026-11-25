package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"oddlyproxifier/internal/config"
)

// UDP relaying as SOCKS5 defines it (RFC 1928, section 7): a TCP connection
// asks the proxy for an association and stays open for as long as it is
// needed; the datagrams themselves travel outside of it, each one prefixed
// with a small header that names the far end.

// MaxUDPHeader is the size of the largest header a relayed datagram can have.
const MaxUDPHeader = 4 + 1 + 255 + 2

// ErrNoUDP marks proxies and routes that cannot carry UDP at all, be it for
// their kind or because the server says so.
var ErrNoUDP = errors.New("cannot carry UDP")

// AppendUDPAddr appends the datagram header for the address ap to b.
func AppendUDPAddr(b []byte, ap netip.AddrPort) []byte {
	ip := ap.Addr().Unmap()
	if ip.Is4() {
		b = append(b, 0, 0, 0, 1)
	} else {
		b = append(b, 0, 0, 0, 4)
	}
	b = append(b, ip.WithZone("").AsSlice()...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

// AppendUDPHeader appends the datagram header for host:port to b. host is a
// name or an address literal.
func AppendUDPHeader(b []byte, host string, port int) ([]byte, error) {
	if port < 0 || port > 65535 {
		return nil, errors.New("bad port")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return AppendUDPAddr(b, netip.AddrPortFrom(ip, uint16(port))), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("bad hostname length")
	}
	b = append(b, 0, 0, 0, 3, byte(len(host)))
	b = append(b, host...)
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// ParseUDPHeader splits a relayed datagram into the address in its header and
// the payload. Exactly one of host and ip is set. Fragments are refused: no
// client in use sends them, and reassembly is optional in the protocol.
func ParseUDPHeader(b []byte) (host string, ip netip.Addr, port int, payload []byte, err error) {
	if len(b) < 4 {
		return "", netip.Addr{}, 0, nil, errors.New("datagram shorter than its header")
	}
	if b[2] != 0 {
		return "", netip.Addr{}, 0, nil, errors.New("fragmented datagram")
	}
	rest := b[4:]
	switch b[3] {
	case 1:
		if len(rest) < 4+2 {
			return "", netip.Addr{}, 0, nil, errors.New("datagram shorter than its header")
		}
		ip, rest = netip.AddrFrom4([4]byte(rest[:4])), rest[4:]
	case 4:
		if len(rest) < 16+2 {
			return "", netip.Addr{}, 0, nil, errors.New("datagram shorter than its header")
		}
		ip, rest = netip.AddrFrom16([16]byte(rest[:16])).Unmap(), rest[16:]
	case 3:
		if len(rest) < 1 || rest[0] == 0 || len(rest) < 1+int(rest[0])+2 {
			return "", netip.Addr{}, 0, nil, errors.New("datagram shorter than its header")
		}
		host, rest = string(rest[1:1+int(rest[0])]), rest[1+int(rest[0]):]
	default:
		return "", netip.Addr{}, 0, nil, fmt.Errorf("address type %d", b[3])
	}
	return host, ip, int(binary.BigEndian.Uint16(rest)), rest[2:], nil
}

// Associate asks the SOCKS5 proxy reachable over c to relay UDP datagrams
// and returns the address they have to be sent to. The association lasts
// until c is closed.
func (h *Hop) Associate(ctx context.Context, c net.Conn) (netip.AddrPort, error) {
	if h.cfg.Type != config.TypeSOCKS5 {
		return netip.AddrPort{}, fmt.Errorf("%s (%s): %w", h.cfg.Name, h.cfg.Type, ErrNoUDP)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	// The request names the address the datagrams will come from. All zeros
	// stands for "not known", which is the truth behind any address translator.
	host, port, err := socks5Request(c, h.cfg.Username, h.cfg.Password, 3, "0.0.0.0", 0)
	if errors.Is(err, ErrNoUDP) {
		return netip.AddrPort{}, fmt.Errorf("%s (%s): %w", h.cfg.Name, h.cfg.Type, err)
	}
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%s (%s): UDP association: %w", h.cfg.Name, h.cfg.Type, err)
	}
	_ = c.SetDeadline(time.Time{})
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%s (%s): UDP association: the proxy names its relay %q instead of giving an address",
			h.cfg.Name, h.cfg.Type, host)
	}
	ip = ip.Unmap()
	// Proxies behind an address translator, and ones that listen on every
	// address, report where they are bound rather than where they can be
	// reached. The address the TCP connection went to is the better one then.
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		server := ta.AddrPort().Addr().Unmap()
		if ip.IsUnspecified() || ip.IsLoopback() && !server.IsLoopback() {
			ip = server
		}
	}
	if !ip.IsValid() || ip.IsUnspecified() || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s (%s): UDP association: the proxy gave no usable relay address",
			h.cfg.Name, h.cfg.Type)
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

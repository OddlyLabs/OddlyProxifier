// Package intercept redirects outbound TCP connections of other processes
// to the engine's transparent listener and recovers their original
// destination. Each platform has its own backend:
//
//	windows  OddlyDrv.sys (WFP ALE_CONNECT_REDIRECT callout)
//	linux    nftables / iptables REDIRECT in the nat OUTPUT hook
//	darwin   pf rdr + route-to (experimental)
package intercept

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"syscall"
)

type Mode int

const (
	// ModeAll intercepts every connection that is not bypassed.
	ModeAll Mode = iota
	// ModeApps intercepts only connections made by the listed applications.
	// The engine selects it when no other application can ever be proxied,
	// which keeps unrelated traffic completely untouched.
	ModeApps
)

// Policy is the coarse pre-filter pushed down to the platform. Everything
// that gets intercepted is still classified by the full rule set in the
// engine; the policy only decides what never needs to be looked at.
type Policy struct {
	Port       int  // transparent listener port
	IPv6       bool // also intercept IPv6
	TargetPort int  // debug aid: intercept only this destination port (0 = all)

	BypassNets []netip.Prefix // destinations that are never intercepted
	ForceNets  []netip.Prefix // destinations that are always intercepted (fake-IP range)

	Mode        Mode
	Apps        []string // ModeApps: lower-case executable name globs
	ExcludeApps []string // executable name globs that are never intercepted
	ExcludePIDs []uint32 // processes that are never intercepted

	BlockQUIC bool // reject UDP/443 of intercepted traffic so that clients fall back to TCP
	DNSPort   int  // redirect outbound DNS (UDP/53) to this local port, 0 = off
}

// Origin describes an intercepted connection.
type Origin struct {
	Dst netip.AddrPort // where the application wanted to go
	PID uint32         // owning process when the platform reports it, else 0
}

// Backend is implemented once per platform.
type Backend interface {
	Name() string
	// Listen opens the listener(s) redirected connections arrive on.
	Listen(port int, ipv6 bool) ([]net.Listener, error)
	// Apply installs the redirection, or updates it when already active.
	Apply(p Policy) error
	// Stop removes the redirection. It is safe to call when not active.
	Stop() error
	// Reset removes redirection that an earlier instance left behind when it
	// died. The engine calls it once, before anything else.
	Reset() error
	// Origin returns the original destination of an accepted connection.
	Origin(c net.Conn) (Origin, error)
	// DialControl marks the engine's own sockets so that they are never
	// intercepted. It may return nil when the platform excludes by PID.
	DialControl() func(network, address string, c syscall.RawConn) error
	// Info reports backend counters for the UI.
	Info() map[string]any
}

var ErrUnsupported = errors.New("transparent interception is not supported on this platform")

// alwaysBypass lists destinations no backend ever intercepts.
var alwaysBypass = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("ff00::/8"),
}

// splitFamilies separates prefixes by address family and drops entries that
// are already covered by a wider one, so that the result can be used as a
// non-overlapping set.
func splitFamilies(nets []netip.Prefix) (v4, v6 []netip.Prefix) {
	norm := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		if !n.IsValid() {
			continue
		}
		a := n.Addr().WithZone("")
		bits := n.Bits()
		if a.Is4In6() {
			if bits < 96 {
				continue
			}
			a, bits = a.Unmap(), bits-96
		}
		if p, err := a.Prefix(bits); err == nil {
			norm = append(norm, p)
		}
	}
	sort.Slice(norm, func(i, j int) bool {
		if norm[i].Bits() != norm[j].Bits() {
			return norm[i].Bits() < norm[j].Bits()
		}
		return norm[i].Addr().Less(norm[j].Addr())
	})
	covered := func(list []netip.Prefix, p netip.Prefix) bool {
		for _, q := range list {
			if q.Contains(p.Addr()) {
				return true
			}
		}
		return false
	}
	for _, p := range norm {
		if p.Addr().Is4() {
			if !covered(v4, p) {
				v4 = append(v4, p)
			}
		} else if !covered(v6, p) {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

func tcpAddrPort(a net.Addr) (netip.AddrPort, bool) {
	t, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := t.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// tcpConn unwraps c down to the *net.TCPConn that owns the socket.
func tcpConn(c net.Conn) (*net.TCPConn, error) {
	for {
		switch v := c.(type) {
		case *net.TCPConn:
			return v, nil
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		default:
			return nil, errors.New("not a TCP connection")
		}
	}
}

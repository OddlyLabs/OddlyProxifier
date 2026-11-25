//go:build darwin

package intercept

// EXPERIMENTAL: this backend follows the documented pf "rdr + route-to"
// recipe but has not been exercised on real hardware.
//
// pf cannot match on the owning process, so the engine (running as root) is
// excluded with "user != root": connections of root-owned daemons are not
// intercepted either.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// The stock /etc/pf.conf evaluates "com.apple/*" anchors, which lets the
	// rules load without rewriting the main ruleset.
	pfAnchor = "com.apple/250.OddlyProxifier"

	pfOut = 2
	// _IOWR('D', 23, struct pfioc_natlook), sizeof == 84
	diocNatLook = 0xC0000000 | (84 << 16) | ('D' << 8) | 23
)

// struct pfioc_natlook (xnu bsd/net/pfvar.h)
type pfNatLook struct {
	saddr, daddr, rsaddr, rdaddr       [16]byte
	sxport, dxport, rsxport, rdxport   [4]byte
	af, proto, protoVariant, direction uint8
}

type darwinBackend struct {
	mu        sync.Mutex
	active    bool
	token     string
	pf        *os.File
	guardStop func()
	guardErr  string
}

func New() Backend { return &darwinBackend{} }

func (b *darwinBackend) Reset() error { return cleanup() }

func (b *darwinBackend) Name() string { return "pf rdr (experimental)" }

func (b *darwinBackend) DialControl() func(string, string, syscall.RawConn) error { return nil }

func (b *darwinBackend) Listen(port int, ipv6 bool) ([]net.Listener, error) {
	l4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	out := []net.Listener{l4}
	if ipv6 {
		if l6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port))); err == nil {
			out = append(out, l6)
		}
	}
	return out, nil
}

func pfTable(nets []netip.Prefix) string {
	parts := make([]string, len(nets))
	for i, n := range nets {
		parts[i] = n.String()
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func pfRules(p Policy) string {
	bypass4, bypass6 := splitFamilies(append(append([]netip.Prefix{}, alwaysBypass...), p.BypassNets...))
	port := ""
	if p.TargetPort > 0 {
		port = fmt.Sprintf(" port %d", p.TargetPort)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table <oddly_bypass4> const %s\n", pfTable(bypass4))
	if p.IPv6 {
		fmt.Fprintf(&b, "table <oddly_bypass6> const %s\n", pfTable(bypass6))
	}
	// Translation rules first, then filter rules.
	fmt.Fprintf(&b, "rdr pass on lo0 inet proto tcp from any to ! <oddly_bypass4>%s -> 127.0.0.1 port %d\n", port, p.Port)
	if p.IPv6 {
		fmt.Fprintf(&b, "rdr pass on lo0 inet6 proto tcp from any to ! <oddly_bypass6>%s -> ::1 port %d\n", port, p.Port)
	}
	fmt.Fprintf(&b, "pass out route-to (lo0 127.0.0.1) inet proto tcp from any to ! <oddly_bypass4>%s user != root keep state\n", port)
	if p.IPv6 {
		fmt.Fprintf(&b, "pass out route-to (lo0 ::1) inet6 proto tcp from any to ! <oddly_bypass6>%s user != root keep state\n", port)
	}
	if p.BlockQUIC {
		b.WriteString("block return out inet proto udp from any to ! <oddly_bypass4> port 443 user != root\n")
		if p.IPv6 {
			b.WriteString("block return out inet6 proto udp from any to ! <oddly_bypass6> port 443 user != root\n")
		}
	}
	return b.String()
}

var pfTokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

func (b *darwinBackend) Apply(p Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if os.Geteuid() != 0 {
		return errors.New("root privileges are required to load pf rules")
	}
	if b.pf == nil {
		f, err := os.OpenFile("/dev/pf", os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("open /dev/pf: %w", err)
		}
		b.pf = f
	}
	if b.guardStop == nil {
		if stop, err := startGuard(); err != nil {
			b.guardErr = err.Error()
		} else {
			b.guardStop, b.guardErr = stop, ""
		}
	}
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(pfRules(p))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: %v: %s", err, bytes.TrimSpace(out))
	}
	if b.token == "" {
		// -E enables pf and returns a reference token, so that disabling it
		// later does not turn pf off for other users of it.
		out, _ := exec.Command("pfctl", "-E").CombinedOutput()
		if m := pfTokenRe.FindSubmatch(out); m != nil {
			b.token = string(m[1])
		}
	}
	b.active = true
	return nil
}

func (b *darwinBackend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// The guard may be running even though Apply failed half-way.
	defer func() {
		if b.guardStop != nil {
			b.guardStop()
			b.guardStop = nil
		}
	}()
	if !b.active {
		return nil
	}
	b.active = false
	_ = cleanup()
	if b.token != "" {
		_ = exec.Command("pfctl", "-X", b.token).Run()
		b.token = ""
	}
	if b.pf != nil {
		_ = b.pf.Close()
		b.pf = nil
	}
	return nil
}

func cleanup() error {
	if os.Geteuid() != 0 {
		return nil
	}
	return exec.Command("pfctl", "-a", pfAnchor, "-F", "all").Run()
}

// Origin asks pf for the state entry of the redirected connection.
func (b *darwinBackend) Origin(c net.Conn) (Origin, error) {
	remote, ok1 := tcpAddrPort(c.RemoteAddr())
	local, ok2 := tcpAddrPort(c.LocalAddr())
	if !ok1 || !ok2 {
		return Origin{}, errors.New("not a TCP connection")
	}
	b.mu.Lock()
	pf := b.pf
	b.mu.Unlock()
	if pf == nil {
		return Origin{}, errors.New("pf is not open")
	}
	nl := pfNatLook{proto: syscall.IPPROTO_TCP, direction: pfOut}
	if remote.Addr().Is4() {
		nl.af = syscall.AF_INET
		r, l := remote.Addr().As4(), local.Addr().As4()
		copy(nl.saddr[:], r[:])
		copy(nl.daddr[:], l[:])
	} else {
		nl.af = syscall.AF_INET6
		nl.saddr, nl.daddr = remote.Addr().As16(), local.Addr().As16()
	}
	nl.sxport[0], nl.sxport[1] = byte(remote.Port()>>8), byte(remote.Port())
	nl.dxport[0], nl.dxport[1] = byte(local.Port()>>8), byte(local.Port())
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, pf.Fd(), diocNatLook, uintptr(unsafe.Pointer(&nl))); errno != 0 {
		return Origin{}, fmt.Errorf("DIOCNATLOOK: %w", errno)
	}
	port := uint16(nl.rdxport[0])<<8 | uint16(nl.rdxport[1])
	var addr netip.Addr
	if nl.af == syscall.AF_INET {
		addr = netip.AddrFrom4([4]byte(nl.rdaddr[:4]))
	} else {
		addr = netip.AddrFrom16(nl.rdaddr)
	}
	return Origin{Dst: netip.AddrPortFrom(addr, port)}, nil
}

func (b *darwinBackend) Info() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	info := map[string]any{"active": b.active, "impl": "pf", "experimental": true}
	if b.guardErr != "" {
		info["guard_error"] = b.guardErr
	}
	return info
}

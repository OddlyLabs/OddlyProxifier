//go:build linux

package intercept

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// fwMark tags the engine's own sockets (SO_MARK) so that the rules skip them.
	fwMark = 0x4f44

	tableName = "oddlyproxifier"
	iptChain  = "ODDLYPROXIFIER"

	soOriginalDst = 80 // SO_ORIGINAL_DST and IP6T_SO_ORIGINAL_DST
)

type linuxBackend struct {
	mu        sync.Mutex
	active    bool
	impl      string // "nftables" or "iptables"
	guardStop func()
	guardErr  string
}

func (b *linuxBackend) Reset() error { return cleanup() }

// ensureGuard starts the watchdog that removes the rules should this process
// die. b.mu must be held.
func (b *linuxBackend) ensureGuard() {
	if b.guardStop != nil {
		return
	}
	stop, err := startGuard()
	if err != nil {
		b.guardErr = err.Error()
		return
	}
	b.guardStop, b.guardErr = stop, ""
}

func New() Backend { return &linuxBackend{} }

func (b *linuxBackend) Name() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.impl == "" {
		return "netfilter REDIRECT"
	}
	return b.impl + " REDIRECT"
}

// Listen binds the loopback addresses: REDIRECT in the OUTPUT hook maps
// locally generated connections to 127.0.0.1 / ::1.
func (b *linuxBackend) Listen(port int, ipv6 bool) ([]net.Listener, error) {
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

// DialControl marks the engine's sockets. Without CAP_NET_ADMIN the mark
// cannot be set, but then no redirection can be installed either.
func (b *linuxBackend) DialControl() func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		_ = c.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, fwMark)
		})
		return nil
	}
}

func (b *linuxBackend) Apply(p Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if os.Geteuid() != 0 {
		return errors.New("root privileges are required to install the redirection rules")
	}
	b.ensureGuard()
	var nftErr error
	if _, err := exec.LookPath("nft"); err == nil {
		if nftErr = runInput(nftScript(p), "nft", "-f", "-"); nftErr == nil {
			if b.impl == "iptables" {
				iptCleanup()
			}
			b.impl, b.active = "nftables", true
			return nil
		}
	} else {
		nftErr = err
	}
	if err := iptApply(p); err != nil {
		return fmt.Errorf("nftables: %v; iptables: %w", nftErr, err)
	}
	b.impl, b.active = "iptables", true
	return nil
}

func (b *linuxBackend) Stop() error {
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
	return cleanup()
}

// cleanup removes everything Apply may have installed. It is also what the
// guard process runs when the engine dies.
func cleanup() error {
	if os.Geteuid() != 0 {
		return nil
	}
	if _, err := exec.LookPath("nft"); err == nil {
		for _, fam := range []string{"ip", "ip6"} {
			// Declaring the table first makes the delete succeed either way.
			_ = runInput(fmt.Sprintf("table %s %s\ndelete table %s %s\n", fam, tableName, fam, tableName), "nft", "-f", "-")
		}
	}
	iptCleanup()
	return nil
}

func (b *linuxBackend) Origin(c net.Conn) (Origin, error) {
	tc, err := tcpConn(c)
	if err != nil {
		return Origin{}, err
	}
	local, ok := tcpAddrPort(tc.LocalAddr())
	if !ok {
		return Origin{}, errors.New("no local address")
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return Origin{}, err
	}
	var dst netip.AddrPort
	var serr error
	if err := rc.Control(func(fd uintptr) {
		if local.Addr().Is4() {
			// struct sockaddr_in fits into an ipv6_mreq-sized buffer.
			var m *unix.IPv6Mreq
			if m, serr = unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, soOriginalDst); serr == nil {
				dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(m.Multiaddr[4:8])),
					binary.BigEndian.Uint16(m.Multiaddr[2:4]))
			}
			return
		}
		// struct sockaddr_in6 fits into an ip6_mtuinfo-sized buffer.
		var m *unix.IPv6MTUInfo
		if m, serr = unix.GetsockoptIPv6MTUInfo(int(fd), unix.SOL_IPV6, soOriginalDst); serr == nil {
			// Port is stored in network byte order; read it back bytewise.
			pb := (*[2]byte)(unsafe.Pointer(&m.Addr.Port))
			port := uint16(pb[0])<<8 | uint16(pb[1])
			addr := netip.AddrFrom16(m.Addr.Addr)
			if m.Addr.Scope_id != 0 && addr.IsLinkLocalUnicast() {
				addr = addr.WithZone(strconv.FormatUint(uint64(m.Addr.Scope_id), 10))
			}
			dst = netip.AddrPortFrom(addr, port)
		}
	}); err != nil {
		return Origin{}, err
	}
	if serr != nil {
		return Origin{}, fmt.Errorf("SO_ORIGINAL_DST: %w", serr)
	}
	return Origin{Dst: dst}, nil
}

func (b *linuxBackend) Info() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	info := map[string]any{"active": b.active, "impl": b.impl}
	if b.guardErr != "" {
		info["guard_error"] = b.guardErr
	}
	return info
}

// ------------------------------------------------------------------ nftables

func nftSet(nets []netip.Prefix) string {
	parts := make([]string, len(nets))
	for i, n := range nets {
		parts[i] = n.String()
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func nftScript(p Policy) string {
	force4, force6 := splitFamilies(p.ForceNets)
	bypass4, bypass6 := splitFamilies(append(append([]netip.Prefix{}, alwaysBypass...), p.BypassNets...))

	var b strings.Builder
	family := func(fam, addr, loop string, force, bypass []netip.Prefix) {
		fmt.Fprintf(&b, "table %s %s\ndelete table %s %s\n", fam, tableName, fam, tableName)
		fmt.Fprintf(&b, "table %s %s {\n", fam, tableName)
		b.WriteString("\tchain nat_out {\n\t\ttype nat hook output priority -100; policy accept;\n")
		fmt.Fprintf(&b, "\t\tmeta mark 0x%x return\n", fwMark)
		if len(force) > 0 {
			fmt.Fprintf(&b, "\t\t%s daddr %s meta l4proto tcp redirect to :%d\n", addr, nftSet(force), p.Port)
		}
		if p.DNSPort > 0 {
			fmt.Fprintf(&b, "\t\t%s daddr != %s udp dport 53 redirect to :%d\n", addr, loop, p.DNSPort)
		}
		if len(bypass) > 0 {
			fmt.Fprintf(&b, "\t\t%s daddr %s return\n", addr, nftSet(bypass))
		}
		if p.TargetPort > 0 {
			fmt.Fprintf(&b, "\t\ttcp dport %d redirect to :%d\n", p.TargetPort, p.Port)
		} else {
			fmt.Fprintf(&b, "\t\tmeta l4proto tcp redirect to :%d\n", p.Port)
		}
		b.WriteString("\t}\n")
		if p.BlockQUIC {
			b.WriteString("\tchain filter_out {\n\t\ttype filter hook output priority 0; policy accept;\n")
			fmt.Fprintf(&b, "\t\tmeta mark 0x%x return\n", fwMark)
			if len(bypass) > 0 {
				fmt.Fprintf(&b, "\t\t%s daddr %s return\n", addr, nftSet(bypass))
			}
			b.WriteString("\t\tudp dport 443 reject\n\t}\n")
		}
		b.WriteString("}\n")
	}
	family("ip", "ip", "127.0.0.0/8", force4, bypass4)
	if p.IPv6 {
		family("ip6", "ip6", "::1", force6, bypass6)
	} else {
		fmt.Fprintf(&b, "table ip6 %s\ndelete table ip6 %s\n", tableName, tableName)
	}
	return b.String()
}

// ------------------------------------------------------------------ iptables

func iptRules(p Policy, v6 bool) string {
	force4, force6 := splitFamilies(p.ForceNets)
	bypass4, bypass6 := splitFamilies(append(append([]netip.Prefix{}, alwaysBypass...), p.BypassNets...))
	force, bypass, loop := force4, bypass4, "127.0.0.0/8"
	if v6 {
		force, bypass, loop = force6, bypass6, "::1/128"
	}
	var b strings.Builder
	b.WriteString("*nat\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n", iptChain)
	fmt.Fprintf(&b, "-A %s -m mark --mark 0x%x -j RETURN\n", iptChain, fwMark)
	for _, n := range force {
		fmt.Fprintf(&b, "-A %s -d %s -p tcp -j REDIRECT --to-ports %d\n", iptChain, n, p.Port)
	}
	if p.DNSPort > 0 {
		fmt.Fprintf(&b, "-A %s ! -d %s -p udp --dport 53 -j REDIRECT --to-ports %d\n", iptChain, loop, p.DNSPort)
	}
	for _, n := range bypass {
		fmt.Fprintf(&b, "-A %s -d %s -j RETURN\n", iptChain, n)
	}
	if p.TargetPort > 0 {
		fmt.Fprintf(&b, "-A %s -p tcp --dport %d -j REDIRECT --to-ports %d\n", iptChain, p.TargetPort, p.Port)
	} else {
		fmt.Fprintf(&b, "-A %s -p tcp -j REDIRECT --to-ports %d\n", iptChain, p.Port)
	}
	b.WriteString("COMMIT\n*filter\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n", iptChain)
	if p.BlockQUIC {
		fmt.Fprintf(&b, "-A %s -m mark --mark 0x%x -j RETURN\n", iptChain, fwMark)
		for _, n := range bypass {
			fmt.Fprintf(&b, "-A %s -d %s -j RETURN\n", iptChain, n)
		}
		fmt.Fprintf(&b, "-A %s -p udp --dport 443 -j REJECT\n", iptChain)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func iptApply(p Policy) error {
	type fam struct {
		cmd string
		v6  bool
	}
	fams := []fam{{"iptables", false}}
	if p.IPv6 {
		fams = append(fams, fam{"ip6tables", true})
	}
	for _, f := range fams {
		if _, err := exec.LookPath(f.cmd + "-restore"); err != nil {
			if f.v6 {
				continue // IPv6 interception is best effort
			}
			return err
		}
		// --noflush keeps foreign rules; chains declared in the input are reset.
		if err := runInput(iptRules(p, f.v6), f.cmd+"-restore", "--noflush"); err != nil {
			if f.v6 {
				continue
			}
			return err
		}
		for _, table := range []string{"nat", "filter"} {
			if exec.Command(f.cmd, "-w", "-t", table, "-C", "OUTPUT", "-j", iptChain).Run() != nil {
				if out, err := exec.Command(f.cmd, "-w", "-t", table, "-I", "OUTPUT", "-j", iptChain).CombinedOutput(); err != nil {
					return fmt.Errorf("%s: %v: %s", f.cmd, err, bytes.TrimSpace(out))
				}
			}
		}
	}
	return nil
}

func iptCleanup() {
	for _, cmd := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(cmd); err != nil {
			continue
		}
		for _, table := range []string{"nat", "filter"} {
			// Only touch tables that actually carry our chain.
			if exec.Command(cmd, "-w", "-t", table, "-nL", iptChain).Run() != nil {
				continue
			}
			for exec.Command(cmd, "-w", "-t", table, "-D", "OUTPUT", "-j", iptChain).Run() == nil {
			}
			_ = exec.Command(cmd, "-w", "-t", table, "-F", iptChain).Run()
			_ = exec.Command(cmd, "-w", "-t", table, "-X", iptChain).Run()
		}
	}
}

func runInput(input string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, bytes.TrimSpace(out))
	}
	return nil
}

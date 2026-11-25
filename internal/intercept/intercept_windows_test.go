//go:build windows

package intercept

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
)

var le = binary.LittleEndian

// appAt decodes one application entry of an encoded policy.
func appAt(buf []byte, off int) (kind byte, name string) {
	u := make([]uint16, 0, maxAppChars)
	for i := 0; i < maxAppChars; i++ {
		c := le.Uint16(buf[off+4+i*2:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return buf[off], string(utf16.Decode(u))
}

// The layout the driver reads, byte for byte (driver/oddly_ioctl.h).
func TestEncodePolicyLayout(t *testing.T) {
	p := Policy{
		Port: 39999, IPv6: true, TargetPort: 443,
		ForceNets:   prefixes("198.18.0.0/15"),
		BypassNets:  prefixes("10.0.0.0/8", "fd00::/8"),
		Mode:        ModeApps,
		Apps:        []string{"curl.exe", "fire*.exe"},
		ExcludeApps: []string{"svchost.exe"},
		ExcludePIDs: []uint32{4, 1234},
		BlockQUIC:   true,
	}
	buf := encodePolicy(p, true)

	if headerSize != 160 || netSize != 20 || appSize != 132 {
		t.Fatalf("sizes %d/%d/%d differ from the driver's 160/20/132", headerSize, netSize, appSize)
	}
	if want := 160 + 3*20 + 3*132; len(buf) != want || le.Uint32(buf[0:]) != uint32(want) {
		t.Fatalf("%d bytes, size field %d, want %d", len(buf), le.Uint32(buf[0:]), want)
	}
	if v := le.Uint32(buf[4:]); v != 2 {
		t.Errorf("ABI version %d", v)
	}
	if flagEnabled|flagAppsOnly|flagIPv6|flagBlockQUIC != 0xF {
		t.Error("the flag bits differ from the driver's")
	}
	if f := le.Uint32(buf[8:]); f != 0xF {
		t.Errorf("flags %#x", f)
	}
	if pid := le.Uint32(buf[12:]); pid != uint32(os.Getpid()) {
		t.Errorf("engine PID %d, want %d", pid, os.Getpid())
	}
	if port, target := le.Uint16(buf[16:]), le.Uint16(buf[18:]); port != 39999 || target != 443 {
		t.Errorf("ports %d/%d", port, target)
	}
	if a, b, c := le.Uint32(buf[20:]), le.Uint32(buf[24:]), le.Uint32(buf[28:]); a != 2 || b != 3 || c != 3 {
		t.Errorf("counts: %d PIDs, %d nets, %d apps", a, b, c)
	}
	if a, b, c := le.Uint32(buf[32:]), le.Uint32(buf[36:]), le.Uint32(buf[40:]); a != 4 || b != 1234 || c != 0 {
		t.Errorf("excluded PIDs: %d, %d, %d", a, b, c)
	}

	nets := buf[160:]
	wantNets := []struct {
		family, bits, kind byte
		addr               string
	}{
		{4, 15, netForce, "198.18.0.0"}, // forced networks come first
		{4, 8, netBypass, "10.0.0.0"},
		{6, 8, netBypass, "fd00::"},
	}
	for i, w := range wantNets {
		e := nets[i*20 : i*20+20]
		var addr netip.Addr
		if e[0] == 4 {
			addr = netip.AddrFrom4([4]byte(e[4:8]))
			if !bytes.Equal(e[8:20], make([]byte, 12)) {
				t.Errorf("net %d: bytes after an IPv4 address are not zero", i)
			}
		} else {
			addr = netip.AddrFrom16([16]byte(e[4:20]))
		}
		if e[0] != w.family || e[1] != w.bits || e[2] != w.kind || e[3] != 0 || addr.String() != w.addr {
			t.Errorf("net %d: family %d, %d bits, kind %d, %v; want %+v", i, e[0], e[1], e[2], addr, w)
		}
	}

	apps := 160 + 3*20
	wantApps := []struct {
		kind byte
		name string
	}{{appInclude, "curl.exe"}, {appInclude, "fire*.exe"}, {appExclude, "svchost.exe"}}
	for i, w := range wantApps {
		kind, name := appAt(buf, apps+i*132)
		if kind != w.kind || name != w.name {
			t.Errorf("app %d: kind %d, %q; want %+v", i, kind, name, w)
		}
	}
}

func TestEncodePolicyDisabled(t *testing.T) {
	buf := encodePolicy(Policy{}, false)
	if len(buf) != 160 || le.Uint32(buf[0:]) != 160 || le.Uint32(buf[4:]) != abiVersion {
		t.Fatalf("%d bytes, header % x", len(buf), buf[:8])
	}
	if f := le.Uint32(buf[8:]); f != 0 {
		t.Errorf("flags %#x for a disabled policy", f)
	}
}

func names(n int, format string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(format, i)
	}
	return out
}

// What does not fit must fail towards "the engine sees more", never towards
// "the driver skips something a rule wants proxied".
func TestEncodePolicyLimits(t *testing.T) {
	flags := func(buf []byte) uint32 { return le.Uint32(buf[8:]) }
	counts := func(buf []byte) (pids, nets, apps uint32) {
		return le.Uint32(buf[20:]), le.Uint32(buf[24:]), le.Uint32(buf[28:])
	}
	checkSize := func(name string, buf []byte) {
		t.Helper()
		pids, nets, apps := counts(buf)
		if want := 160 + int(nets)*20 + int(apps)*132; len(buf) != want || int(le.Uint32(buf)) != want || pids > maxPIDs {
			t.Errorf("%s: %d bytes for %d nets and %d apps (%d PIDs)", name, len(buf), nets, apps, pids)
		}
	}

	// Too many applications to name: everything is intercepted instead.
	buf := encodePolicy(Policy{Mode: ModeApps, Apps: names(maxApps+1, "app%d.exe"), ExcludeApps: []string{"a.exe"}}, true)
	checkSize("too many apps", buf)
	if _, _, apps := counts(buf); flags(buf)&flagAppsOnly != 0 || apps != 1 {
		t.Errorf("too many apps: flags %#x, %d entries; want all-apps mode with the one exclusion", flags(buf), apps)
	}

	// A name that does not fit into an entry: the same.
	long := strings.Repeat("x", maxAppChars) // one more than fits beside the terminator
	buf = encodePolicy(Policy{Mode: ModeApps, Apps: []string{"ok.exe", long}}, true)
	checkSize("long name", buf)
	if _, _, apps := counts(buf); flags(buf)&flagAppsOnly != 0 || apps != 0 {
		t.Errorf("over-long app name: flags %#x, %d entries", flags(buf), apps)
	}
	fits := strings.Repeat("x", maxAppChars-1)
	buf = encodePolicy(Policy{Mode: ModeApps, Apps: []string{fits}}, true)
	if _, name := appAt(buf, 160); flags(buf)&flagAppsOnly == 0 || name != fits {
		t.Errorf("a name of %d characters must fit: flags %#x, %q", len(fits), flags(buf), name)
	}
	buf = encodePolicy(Policy{Mode: ModeApps, Apps: []string{"a\x00b.exe"}}, true)
	if flags(buf)&flagAppsOnly != 0 {
		t.Error("a name with a NUL in it was passed to the driver")
	}

	// Exclusions only save work; when they do not fit they are left out.
	buf = encodePolicy(Policy{Mode: ModeApps, Apps: []string{"a.exe"}, ExcludeApps: names(maxApps, "skip%d.exe")}, true)
	checkSize("too many exclusions", buf)
	if _, _, apps := counts(buf); flags(buf)&flagAppsOnly == 0 || apps != 1 {
		t.Errorf("too many exclusions: flags %#x, %d entries; want the one included app", flags(buf), apps)
	}
	if kind, name := appAt(buf, 160); kind != appInclude || name != "a.exe" {
		t.Errorf("the included app became kind %d, %q", kind, name)
	}

	// Networks: forced ones survive, bypasses are cut.
	var many []netip.Prefix
	for i := 0; i < maxNets+10; i++ {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24))
	}
	buf = encodePolicy(Policy{ForceNets: prefixes("198.18.0.0/15"), BypassNets: many}, true)
	checkSize("too many nets", buf)
	if _, nets, _ := counts(buf); nets != maxNets {
		t.Errorf("%d networks", nets)
	}
	if e := buf[160:180]; e[2] != netForce || e[1] != 15 {
		t.Errorf("the forced network is not first: % x", e)
	}

	var pids []uint32
	for i := 0; i < maxPIDs+5; i++ {
		pids = append(pids, uint32(1000+i))
	}
	buf = encodePolicy(Policy{ExcludePIDs: pids}, true)
	checkSize("too many PIDs", buf)
	if n, _, _ := counts(buf); n != maxPIDs || le.Uint32(buf[32+(maxPIDs-1)*4:]) != uint32(1000+maxPIDs-1) {
		t.Errorf("%d PIDs", n)
	}
}

func TestIoctlCodes(t *testing.T) {
	// CTL_CODE(DeviceType, Function, Method, Access)
	ctl := func(devType, function, method, access uint32) uint32 {
		return devType<<16 | access<<14 | function<<2 | method
	}
	const (
		fileDeviceUnknown = 0x22
		methodBuffered    = 0
		readData          = 1
		writeData         = 2
	)
	if got := ctl(fileDeviceUnknown, 0x900, methodBuffered, readData); got != ioctlGetVersion {
		t.Errorf("ioctlGetVersion = %#x, CTL_CODE gives %#x", ioctlGetVersion, got)
	}
	if got := ctl(fileDeviceUnknown, 0x901, methodBuffered, readData|writeData); got != ioctlSetPolicy {
		t.Errorf("ioctlSetPolicy = %#x, CTL_CODE gives %#x", ioctlSetPolicy, got)
	}
	if got := ctl(fileDeviceUnknown, 0x902, methodBuffered, readData); got != ioctlGetStats {
		t.Errorf("ioctlGetStats = %#x, CTL_CODE gives %#x", ioctlGetStats, got)
	}
	// _WSAIOW(IOC_VENDOR, 221) = IOC_IN | IOC_VENDOR | 221
	if got := uint32(0x80000000 | 0x18000000 | 221); got != sioQueryWFPConnectionRedirectContext {
		t.Errorf("SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT = %#x, want %#x", sioQueryWFPConnectionRedirectContext, got)
	}
}

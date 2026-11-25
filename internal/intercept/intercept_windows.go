//go:build windows

package intercept

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Interface shared with driver/oddly_ioctl.h. Keep both in sync.
const (
	DriverService = "OddlyDrv"
	devicePath    = `\\.\OddlyDrv`

	abiVersion = 2

	ioctlGetVersion = 0x226400 // CTL_CODE(0x22, 0x900, METHOD_BUFFERED, FILE_READ_DATA)
	ioctlSetPolicy  = 0x22E404 // CTL_CODE(0x22, 0x901, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
	ioctlGetStats   = 0x226408 // CTL_CODE(0x22, 0x902, METHOD_BUFFERED, FILE_READ_DATA)

	flagEnabled   = 0x1
	flagAppsOnly  = 0x2
	flagIPv6      = 0x4
	flagBlockQUIC = 0x8

	maxPIDs     = 32
	maxNets     = 256
	maxApps     = 128
	maxAppChars = 64

	netSize    = 20
	appSize    = 4 + maxAppChars*2
	headerSize = 32 + maxPIDs*4

	netBypass  = 0
	netForce   = 1
	appInclude = 0
	appExclude = 1

	ctxMagic = 0x3243444F // "ODC2"
	ctxSize  = 48

	// _WSAIOW(IOC_VENDOR, 221), see mswsock.h
	sioQueryWFPConnectionRedirectContext = 0x980000DD
)

type winBackend struct {
	mu     sync.Mutex
	dev    windows.Handle
	active bool
}

func New() Backend { return &winBackend{dev: windows.InvalidHandle} }

func (b *winBackend) Name() string { return "OddlyDrv (WFP)" }

func (b *winBackend) DialControl() func(string, string, syscall.RawConn) error { return nil }

// Reset has nothing to do: the driver drops the policy of an engine that died.
func (b *winBackend) Reset() error { return nil }

// Listen binds the wildcard addresses: the driver redirects to 127.0.0.1
// for unbound sockets, but to the connection's own local address when the
// application bound to a specific one, so both must be reachable.
func (b *winBackend) Listen(port int, ipv6 bool) ([]net.Listener, error) {
	l4, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	out := []net.Listener{l4}
	if ipv6 {
		if l6, err := net.Listen("tcp6", net.JoinHostPort("::", strconv.Itoa(port))); err == nil {
			out = append(out, l6)
		}
	}
	return out, nil
}

func (b *winBackend) open() error {
	if b.dev != windows.InvalidHandle {
		return nil
	}
	h, err := openDevice()
	if err != nil {
		// The driver may simply not be running yet.
		if serr := EnsureDriver(); serr != nil {
			return fmt.Errorf("driver unavailable: %w", serr)
		}
		if h, err = openDevice(); err != nil {
			return fmt.Errorf("open %s: %w", devicePath, err)
		}
	}
	var ver [4]byte
	var n uint32
	if err := windows.DeviceIoControl(h, ioctlGetVersion, nil, 0, &ver[0], 4, &n, nil); err != nil {
		windows.CloseHandle(h)
		return fmt.Errorf("driver version query failed (old driver loaded?): %w", err)
	}
	if v := binary.LittleEndian.Uint32(ver[:]); v != abiVersion {
		windows.CloseHandle(h)
		return fmt.Errorf("driver ABI version %d, engine needs %d: reinstall the driver", v, abiVersion)
	}
	b.dev = h
	return nil
}

func openDevice() (windows.Handle, error) {
	p, _ := windows.UTF16PtrFromString(devicePath)
	return windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, 0, 0)
}

func (b *winBackend) Apply(p Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.open(); err != nil {
		return err
	}
	buf := encodePolicy(p, true)
	var n uint32
	if err := windows.DeviceIoControl(b.dev, ioctlSetPolicy, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil {
		return fmt.Errorf("set driver policy: %w", err)
	}
	b.active = true
	return nil
}

// Stop disables redirection. Closing the device handle alone would do it as
// well: the driver drops the policy when its owner goes away, so a crashed
// engine never leaves the machine redirecting into nothing.
func (b *winBackend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == windows.InvalidHandle {
		return nil
	}
	buf := encodePolicy(Policy{}, false)
	var n uint32
	err := windows.DeviceIoControl(b.dev, ioctlSetPolicy, &buf[0], uint32(len(buf)), nil, 0, &n, nil)
	windows.CloseHandle(b.dev)
	b.dev = windows.InvalidHandle
	b.active = false
	return err
}

func encodePolicy(p Policy, enabled bool) []byte {
	type netEntry struct {
		kind byte
		pfx  netip.Prefix
	}
	var nets []netEntry
	for _, n := range p.ForceNets {
		nets = append(nets, netEntry{netForce, n})
	}
	for _, n := range p.BypassNets {
		nets = append(nets, netEntry{netBypass, n})
	}
	if len(nets) > maxNets {
		nets = nets[:maxNets] // dropping bypass entries is safe: the engine still decides
	}

	type appEntry struct {
		kind byte
		pat  []uint16
	}
	var apps []appEntry
	mode := p.Mode
	add := func(kind byte, pats []string) bool {
		for _, s := range pats {
			u, err := windows.UTF16FromString(s) // fails on an embedded NUL
			if err != nil || len(u) > maxAppChars || len(apps) >= maxApps {
				return false
			}
			apps = append(apps, appEntry{kind, u})
		}
		return true
	}
	if mode == ModeApps && !add(appInclude, p.Apps) {
		mode, apps = ModeAll, nil // too many / too long: fall back to intercepting everything
	}
	n := len(apps)
	if !add(appExclude, p.ExcludeApps) {
		apps = apps[:n] // excludes are an optimisation only
	}

	pids := append([]uint32{}, p.ExcludePIDs...)
	if len(pids) > maxPIDs {
		pids = pids[:maxPIDs]
	}

	size := headerSize + len(nets)*netSize + len(apps)*appSize
	buf := make([]byte, size)
	le := binary.LittleEndian
	var flags uint32
	if enabled {
		flags |= flagEnabled
	}
	if mode == ModeApps {
		flags |= flagAppsOnly
	}
	if p.IPv6 {
		flags |= flagIPv6
	}
	if p.BlockQUIC {
		flags |= flagBlockQUIC
	}
	le.PutUint32(buf[0:], uint32(size))
	le.PutUint32(buf[4:], abiVersion)
	le.PutUint32(buf[8:], flags)
	le.PutUint32(buf[12:], uint32(os.Getpid()))
	le.PutUint16(buf[16:], uint16(p.Port))
	le.PutUint16(buf[18:], uint16(p.TargetPort))
	le.PutUint32(buf[20:], uint32(len(pids)))
	le.PutUint32(buf[24:], uint32(len(nets)))
	le.PutUint32(buf[28:], uint32(len(apps)))
	for i, pid := range pids {
		le.PutUint32(buf[32+i*4:], pid)
	}
	off := headerSize
	for _, e := range nets {
		a := e.pfx.Addr()
		if a.Is4() {
			buf[off] = 4
		} else {
			buf[off] = 6
		}
		buf[off+1] = byte(e.pfx.Bits())
		buf[off+2] = e.kind
		copy(buf[off+4:off+20], a.AsSlice())
		off += netSize
	}
	for _, e := range apps {
		buf[off] = e.kind
		for i, c := range e.pat {
			le.PutUint16(buf[off+4+i*2:], c)
		}
		off += appSize
	}
	return buf
}

// Origin reads the redirect context the driver attached to the connection.
func (b *winBackend) Origin(c net.Conn) (Origin, error) {
	tc, err := tcpConn(c)
	if err != nil {
		return Origin{}, err
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return Origin{}, err
	}
	var buf [ctxSize]byte
	var n uint32
	var ioErr error
	if err := rc.Control(func(fd uintptr) {
		ioErr = windows.WSAIoctl(windows.Handle(fd), sioQueryWFPConnectionRedirectContext,
			nil, 0, &buf[0], uint32(len(buf)), &n, nil, 0)
	}); err != nil {
		return Origin{}, err
	}
	if ioErr != nil {
		return Origin{}, fmt.Errorf("no redirect context: %w", ioErr)
	}
	le := binary.LittleEndian
	if n < ctxSize || le.Uint32(buf[0:]) != ctxMagic {
		return Origin{}, errors.New("malformed redirect context")
	}
	pid := le.Uint32(buf[4:])
	port := binary.BigEndian.Uint16(buf[10:]) // network order
	var addr netip.Addr
	switch le.Uint16(buf[8:]) {
	case 4:
		addr = netip.AddrFrom4([4]byte(buf[12:16]))
	case 6:
		addr = netip.AddrFrom16([16]byte(buf[12:28]))
		if zone := le.Uint32(buf[44:]); zone != 0 && addr.IsLinkLocalUnicast() {
			addr = addr.WithZone(strconv.FormatUint(uint64(zone), 10))
		}
	default:
		return Origin{}, errors.New("malformed redirect context")
	}
	return Origin{Dst: netip.AddrPortFrom(addr, port), PID: pid}, nil
}

func (b *winBackend) Info() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	info := map[string]any{"active": b.active}
	if b.dev == windows.InvalidHandle {
		return info
	}
	var buf [40]byte
	var n uint32
	if windows.DeviceIoControl(b.dev, ioctlGetStats, nil, 0, &buf[0], uint32(len(buf)), &n, nil) == nil && n >= 40 {
		le := binary.LittleEndian
		info["classified"] = le.Uint64(buf[0:])
		info["redirected"] = le.Uint64(buf[8:])
		info["bypassed"] = le.Uint64(buf[16:])
		info["quic_blocked"] = le.Uint64(buf[24:])
		info["errors"] = le.Uint64(buf[32:])
	}
	return info
}

// ------------------------------------------------------------ driver service

// DriverStatus describes the kernel driver service.
type DriverStatus struct {
	Installed bool
	Running   bool
	Path      string
}

// QueryDriver asks for read access only, so it also works without
// administrator rights.
func QueryDriver() (DriverStatus, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return DriverStatus{}, fmt.Errorf("service manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(DriverService)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return DriverStatus{}, nil
		}
		return DriverStatus{}, fmt.Errorf("driver service: %w", err)
	}
	s := &mgr.Service{Name: DriverService, Handle: h}
	defer s.Close()
	st := DriverStatus{Installed: true}
	if q, err := s.Query(); err == nil {
		st.Running = q.State == svc.Running
	}
	if c, err := s.Config(); err == nil {
		st.Path = c.BinaryPathName
	}
	return st, nil
}

func driverInstallPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "OddlyDrv.sys")
}

// FindDriverFile looks for OddlyDrv.sys next to the executable.
func FindDriverFile() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	for _, p := range []string{
		filepath.Join(dir, "OddlyDrv.sys"),
		filepath.Join(dir, "driver", "OddlyDrv.sys"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// InstallDriver copies the driver into System32\drivers and registers a
// demand-start kernel service for it.
func InstallDriver(src string) error {
	if src == "" {
		if src = FindDriverFile(); src == "" {
			return errors.New("OddlyDrv.sys not found next to the executable")
		}
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	_ = StopDriver()
	dst := driverInstallPath()
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("copy driver to %s: %w", dst, err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(DriverService); err == nil {
		s.Close()
		return nil // already registered; the file was refreshed
	}
	name, _ := windows.UTF16PtrFromString(DriverService)
	disp, _ := windows.UTF16PtrFromString("OddlyProxifier WFP Callout Driver")
	bin, _ := windows.UTF16PtrFromString(`System32\drivers\OddlyDrv.sys`)
	deps, _ := windows.UTF16FromString("BFE")
	deps = append(deps, 0) // double-NUL terminated list
	h, err := windows.CreateService(m.Handle, name, disp, windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_KERNEL_DRIVER, windows.SERVICE_DEMAND_START, windows.SERVICE_ERROR_NORMAL,
		bin, nil, nil, &deps[0], nil, nil)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	windows.CloseServiceHandle(h)
	return nil
}

func StartDriver() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(DriverService)
	if err != nil {
		return fmt.Errorf("driver service is not installed: %w", err)
	}
	defer s.Close()
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		if errors.Is(err, windows.ERROR_INVALID_IMAGE_HASH) {
			return fmt.Errorf("Windows refused the driver signature (enable test signing or use a production-signed build): %w", err)
		}
		return fmt.Errorf("start driver: %w", err)
	}
	return nil
}

func StopDriver() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(DriverService)
	if err != nil {
		return nil
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop driver: %w", err)
	}
	for i := 0; i < 50; i++ {
		if q, err := s.Query(); err != nil || q.State == svc.Stopped {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func UninstallDriver() error {
	if err := StopDriver(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(DriverService); err == nil {
		err = s.Delete()
		s.Close()
		if err != nil {
			return fmt.Errorf("delete service: %w", err)
		}
	}
	if err := os.Remove(driverInstallPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// EnsureDriver gets the driver running, installing it first when the .sys
// file ships next to the executable.
func EnsureDriver() error {
	if !IsElevated() {
		return errors.New("administrator rights are required")
	}
	st, err := QueryDriver()
	if err != nil {
		return err
	}
	if !st.Installed {
		if err := InstallDriver(""); err != nil {
			return err
		}
	}
	return StartDriver()
}

func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

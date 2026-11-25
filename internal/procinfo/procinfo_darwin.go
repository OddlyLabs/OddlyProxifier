//go:build darwin

package procinfo

// EXPERIMENTAL: not exercised on real hardware. The offsets below describe
// the records returned by the net.inet.tcp.pcblist_n sysctl (xnu
// bsd/netinet/in_pcblist.c), whose layout changed with Darwin 22.

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	procCallNumPIDInfo  = 0x2
	procPIDPathInfo     = 0xb
	procPIDPathInfoSize = 1024
)

// rup8(sizeof(xinpcb_n)) + rup8(sizeof(xsocket_n)) + 2*rup8(sizeof(xsockbuf_n))
// + rup8(sizeof(xsockstat_n)), followed by rup8(sizeof(xtcpcb_n)) for TCP.
func pcbItemSize() int {
	rel, _ := syscall.Sysctl("kern.osrelease")
	major, _, _ := strings.Cut(rel, ".")
	n, _ := strconv.Atoi(major)
	if n >= 22 {
		return 408 + 208
	}
	return 384 + 208
}

func findPID(local, _ netip.AddrPort) uint32 {
	buf, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if err != nil {
		return 0
	}
	la := local.Addr().Unmap().WithZone("")
	item := pcbItemSize()
	// The list starts with a 24 byte xinpgen header.
	for i := 24; i+item <= len(buf); i += item {
		inp, so := i, i+104
		if binary.BigEndian.Uint16(buf[inp+18:inp+20]) != local.Port() {
			continue
		}
		vflag := buf[inp+44]
		var src netip.Addr
		switch {
		case vflag&0x1 != 0 && la.Is4():
			src = netip.AddrFrom4([4]byte(buf[inp+76 : inp+80]))
		case vflag&0x2 != 0 && la.Is6():
			src = netip.AddrFrom16([16]byte(buf[inp+64 : inp+80]))
		default:
			continue
		}
		if src != la {
			continue
		}
		return binary.NativeEndian.Uint32(buf[so+68 : so+72]) // xsocket_n.so_last_pid
	}
	return 0
}

func listenerPID(uint16) uint32 { return 0 }

func pathOf(pid uint32) string {
	buf := make([]byte, procPIDPathInfoSize)
	_, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, procCallNumPIDInfo, uintptr(pid),
		procPIDPathInfo, 0, uintptr(unsafe.Pointer(&buf[0])), procPIDPathInfoSize)
	if errno != 0 {
		return ""
	}
	return unix.ByteSliceToString(buf)
}

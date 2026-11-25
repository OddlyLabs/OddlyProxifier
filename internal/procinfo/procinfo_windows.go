//go:build windows

package procinfo

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDListener    = 3 // TCP_TABLE_OWNER_PID_LISTENER
	tcpTableOwnerPIDConnections = 4 // TCP_TABLE_OWNER_PID_CONNECTIONS
	errInsufficientBuffer       = 122

	row4Size = 24 // MIB_TCPROW_OWNER_PID
	row6Size = 56 // MIB_TCP6ROW_OWNER_PID
)

func tcpTable(family, class uint32) []byte {
	size := uint32(64 * 1024)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(family), uintptr(class), 0)
		switch r {
		case 0:
			return buf
		case errInsufficientBuffer:
			size += 16 * 1024 // the table may grow between the two calls
		default:
			return nil
		}
	}
	return nil
}

// findPID scans the system connection table for the socket's owner. The
// remote endpoint is used to tell apart sockets that share a local port.
func findPID(local, remote netip.AddrPort) uint32 {
	la := local.Addr().Unmap().WithZone("")
	ra := remote.Addr().Unmap().WithZone("")
	le := binary.LittleEndian
	if la.Is4() {
		buf := tcpTable(windows.AF_INET, tcpTableOwnerPIDConnections)
		if len(buf) < 4 {
			return 0
		}
		n := int(le.Uint32(buf))
		want := la.As4()
		var fallback uint32
		for i := 0; i < n && 4+(i+1)*row4Size <= len(buf); i++ {
			row := buf[4+i*row4Size:]
			if binary.BigEndian.Uint16(row[8:10]) != local.Port() || [4]byte(row[4:8]) != want {
				continue
			}
			pid := le.Uint32(row[20:24])
			if !remote.IsValid() {
				return pid
			}
			if binary.BigEndian.Uint16(row[16:18]) == remote.Port() && ra.Is4() && [4]byte(row[12:16]) == ra.As4() {
				return pid
			}
			fallback = pid
		}
		return fallback
	}
	buf := tcpTable(windows.AF_INET6, tcpTableOwnerPIDConnections)
	if len(buf) < 4 {
		return 0
	}
	n := int(le.Uint32(buf))
	want := la.As16()
	var fallback uint32
	for i := 0; i < n && 4+(i+1)*row6Size <= len(buf); i++ {
		row := buf[4+i*row6Size:]
		if binary.BigEndian.Uint16(row[20:22]) != local.Port() || [16]byte(row[0:16]) != want {
			continue
		}
		pid := le.Uint32(row[52:56])
		if !remote.IsValid() {
			return pid
		}
		if binary.BigEndian.Uint16(row[44:46]) == remote.Port() && ra.Is6() && [16]byte(row[24:40]) == ra.As16() {
			return pid
		}
		fallback = pid
	}
	return fallback
}

// listenerPID scans the listener tables. Their rows have the same layout as
// connection rows, with the remote fields unused.
func listenerPID(port uint16) uint32 {
	le := binary.LittleEndian
	if buf := tcpTable(windows.AF_INET, tcpTableOwnerPIDListener); len(buf) >= 4 {
		n := int(le.Uint32(buf))
		for i := 0; i < n && 4+(i+1)*row4Size <= len(buf); i++ {
			row := buf[4+i*row4Size:]
			if binary.BigEndian.Uint16(row[8:10]) == port {
				return le.Uint32(row[20:24])
			}
		}
	}
	if buf := tcpTable(windows.AF_INET6, tcpTableOwnerPIDListener); len(buf) >= 4 {
		n := int(le.Uint32(buf))
		for i := 0; i < n && 4+(i+1)*row6Size <= len(buf); i++ {
			row := buf[4+i*row6Size:]
			if binary.BigEndian.Uint16(row[20:22]) == port {
				return le.Uint32(row[52:56])
			}
		}
	}
	return 0
}

func pathOf(pid uint32) string {
	if pid == 4 {
		return "System"
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

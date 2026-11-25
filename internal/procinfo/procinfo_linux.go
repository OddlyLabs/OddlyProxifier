//go:build linux

package procinfo

import (
	"encoding/binary"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	nlHdrLen    = 16
	diagReqLen  = 56 // struct inet_diag_req_v2
	diagMsgLen  = 72 // struct inet_diag_msg
	sockDiagFam = 20 // SOCK_DIAG_BY_FAMILY
)

// sockDiag asks the kernel (NETLINK_SOCK_DIAG, exact lookup) for the socket
// with the given endpoints and returns its inode number and owner UID.
func sockDiag(local, remote netip.AddrPort) (inode, uid uint32, ok bool) {
	la := local.Addr().Unmap().WithZone("")
	ra := remote.Addr().Unmap().WithZone("")
	if !la.IsValid() || !ra.IsValid() || la.Is4() != ra.Is4() {
		return 0, 0, false
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, 0, false
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})

	ne := binary.NativeEndian
	req := make([]byte, nlHdrLen+diagReqLen)
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], sockDiagFam)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST)
	ne.PutUint32(req[8:], 1)
	d := req[nlHdrLen:]
	if la.Is4() {
		d[0] = unix.AF_INET
	} else {
		d[0] = unix.AF_INET6
	}
	d[1] = unix.IPPROTO_TCP
	ne.PutUint32(d[4:], 0xFFFFFFFF) // all states
	binary.BigEndian.PutUint16(d[8:], local.Port())
	binary.BigEndian.PutUint16(d[10:], remote.Port())
	copy(d[12:28], la.AsSlice())
	copy(d[28:44], ra.AsSlice())
	ne.PutUint32(d[48:], 0xFFFFFFFF) // INET_DIAG_NOCOOKIE
	ne.PutUint32(d[52:], 0xFFFFFFFF)

	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, 0, false
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil || n < nlHdrLen+diagMsgLen {
		return 0, 0, false // NLMSG_ERROR replies are shorter than a diag message
	}
	if ne.Uint16(buf[4:6]) != sockDiagFam {
		return 0, 0, false
	}
	m := buf[nlHdrLen:]
	return ne.Uint32(m[68:72]), ne.Uint32(m[64:68]), true
}

func findPID(local, remote netip.AddrPort) uint32 {
	inode, uid, ok := sockDiag(local, remote)
	if !ok || inode == 0 {
		return 0
	}
	return pidByInode(inode, uid)
}

// listenerPID looks the port up in /proc/net/tcp{,6}: one line per socket,
// "sl local_address rem_address st ... uid timeout inode".
func listenerPID(port uint16) uint32 {
	want := strings.ToUpper(strconv.FormatUint(uint64(port)|0x10000, 16)[1:])
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "0A" { // TCP_LISTEN
				continue
			}
			if _, p, ok := strings.Cut(f[1], ":"); !ok || p != want {
				continue
			}
			uid, _ := strconv.ParseUint(f[7], 10, 32)
			inode, _ := strconv.ParseUint(f[9], 10, 32)
			if pid := pidByInode(uint32(inode), uint32(uid)); pid != 0 {
				return pid
			}
		}
	}
	return 0
}

func pidByInode(inode, uid uint32) uint32 {
	target := "socket:[" + strconv.FormatUint(uint64(inode), 10) + "]"
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range ents {
		name := e.Name()
		if name[0] < '0' || name[0] > '9' {
			continue
		}
		dir := "/proc/" + name
		var st unix.Stat_t
		if unix.Stat(dir, &st) != nil || st.Uid != uid {
			continue
		}
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue
		}
		for _, f := range fds {
			if link, err := os.Readlink(dir + "/fd/" + f.Name()); err == nil && link == target {
				pid, _ := strconv.ParseUint(name, 10, 32)
				return uint32(pid)
			}
		}
	}
	return 0
}

func pathOf(pid uint32) string {
	link, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(link, " (deleted)")
}

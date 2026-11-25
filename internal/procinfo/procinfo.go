// Package procinfo finds out which program owns a TCP connection, so that
// rules can match on the application.
package procinfo

import (
	"net/netip"
	"sync"
	"time"
)

// Find returns the process that owns the TCP socket whose local endpoint is
// local and whose peer is remote. It returns 0, "" when the owner cannot be
// determined (insufficient privileges, the process already exited, ...).
func Find(local, remote netip.AddrPort) (pid uint32, path string) {
	pid = findPID(local, remote)
	if pid == 0 {
		return 0, ""
	}
	return pid, PathOf(pid)
}

type cached struct {
	path string
	at   time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[uint32]cached{}
)

type listenerEntry struct {
	pid uint32
	at  time.Time
}

var (
	listenerMu    sync.Mutex
	listenerCache = map[uint16]listenerEntry{}
)

// ListenerPID returns the process listening on the given local TCP port, or
// 0. The answer is cached for a second: it is asked for every proxied
// connection.
func ListenerPID(port uint16) uint32 {
	now := time.Now()
	listenerMu.Lock()
	if c, ok := listenerCache[port]; ok && now.Sub(c.at) < time.Second {
		listenerMu.Unlock()
		return c.pid
	}
	listenerMu.Unlock()
	pid := listenerPID(port)
	listenerMu.Lock()
	listenerCache[port] = listenerEntry{pid, now}
	listenerMu.Unlock()
	return pid
}

// A PID can be reused, so paths are only remembered briefly.
const cacheTTL = 3 * time.Second

// PathOf returns the executable path of pid, or "".
func PathOf(pid uint32) string {
	if pid == 0 {
		return ""
	}
	now := time.Now()
	cacheMu.Lock()
	if c, ok := cache[pid]; ok && now.Sub(c.at) < cacheTTL {
		cacheMu.Unlock()
		return c.path
	}
	cacheMu.Unlock()

	path := pathOf(pid)

	cacheMu.Lock()
	if len(cache) > 4096 {
		for k, c := range cache {
			if now.Sub(c.at) >= cacheTTL {
				delete(cache, k)
			}
		}
	}
	cache[pid] = cached{path, now}
	cacheMu.Unlock()
	return path
}

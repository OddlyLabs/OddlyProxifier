//go:build !windows && !linux && !darwin

package procinfo

import "net/netip"

func findPID(_, _ netip.AddrPort) uint32 { return 0 }
func listenerPID(uint16) uint32          { return 0 }
func pathOf(uint32) string               { return "" }

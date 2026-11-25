//go:build !linux && !darwin

package intercept

// GuardArg is unused on this platform: the Windows driver drops its policy
// by itself when the engine's device handle closes.
const GuardArg = "__guard"

func Cleanup() error { return nil }
func RunGuard()      {}

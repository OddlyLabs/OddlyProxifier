//go:build linux || darwin

package intercept

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// GuardArg is the hidden command line argument that turns the binary into
// the guard process.
const GuardArg = "__guard"

// Cleanup removes redirection rules left behind by an earlier instance.
func Cleanup() error { return cleanup() }

// startGuard launches a small watchdog. Netfilter and pf rules outlive the
// process that installed them, so if the engine is killed the machine would
// keep redirecting every connection into a dead port. The guard holds the
// read end of a pipe and removes the rules as soon as the engine is gone.
//
// stop ends the guard without a cleanup: the caller has removed the rules
// itself, and a late cleanup could hit the rules of the next instance.
func startGuard() (stop func(), err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, GuardArg)
	cmd.Stdin = r
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // survive the terminal going away
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, err
	}
	_ = r.Close()
	go func() { _ = cmd.Wait() }()
	return func() {
		_, _ = w.Write([]byte{'q'})
		_ = w.Close()
	}, nil
}

// RunGuard is the guard process. A byte on stdin means the engine stopped in
// an orderly way; end of file without one means it died, and then the rules
// it left behind are removed.
func RunGuard() {
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
	var b [1]byte
	if n, _ := os.Stdin.Read(b[:]); n > 0 {
		return
	}
	_ = cleanup()
}

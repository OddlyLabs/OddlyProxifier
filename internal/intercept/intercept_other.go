//go:build !windows && !linux && !darwin

package intercept

import (
	"net"
	"syscall"
)

type noBackend struct{}

// New returns a backend that cannot intercept; the engine still works as an
// explicit proxy through its inbound listener.
func New() Backend { return noBackend{} }

func (noBackend) Name() string                                             { return "none" }
func (noBackend) Listen(int, bool) ([]net.Listener, error)                 { return nil, ErrUnsupported }
func (noBackend) Apply(Policy) error                                       { return ErrUnsupported }
func (noBackend) Stop() error                                              { return nil }
func (noBackend) Reset() error                                             { return nil }
func (noBackend) Origin(net.Conn) (Origin, error)                          { return Origin{}, ErrUnsupported }
func (noBackend) DialControl() func(string, string, syscall.RawConn) error { return nil }
func (noBackend) Info() map[string]any                                     { return map[string]any{"active": false} }

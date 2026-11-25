//go:build !windows && !linux && !darwin

package service

import "context"

// IsService is only meaningful on Windows.
func IsService() bool { return false }

// Run is only meaningful on Windows.
func Run(run func(ctx context.Context) error) error { return run(context.Background()) }

func Install(Config) error { return ErrUnsupported }
func Uninstall() error     { return ErrUnsupported }
func Start() error         { return ErrUnsupported }
func Stop() error          { return ErrUnsupported }

func Status() (state, command string, err error) { return "", "", ErrUnsupported }

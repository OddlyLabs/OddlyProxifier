//go:build !windows

package main

import (
	"context"
	"errors"
)

var errNoTray = errors.New("the notification-area icon exists only on Windows; use the web interface")

func wantTray(mode string, _ bool) (bool, error) {
	switch mode {
	case "on":
		return false, errNoTray
	case "off", "auto":
		return false, nil
	}
	return false, errors.New(`-tray must be "on", "off" or "auto"`)
}

func runTray(context.Context, trayClient, bool) bool { return false }

func cmdTray([]string) error { return errNoTray }

// doubleClicked is only ever true on Windows.
func doubleClicked() bool { return false }

func relaunchElevated() bool { return false }

func fatalNotice(error) {}

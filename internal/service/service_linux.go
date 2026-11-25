//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const unitPath = "/etc/systemd/system/" + unitName

// IsService is only meaningful on Windows; systemd starts the program like
// any other.
func IsService() bool { return false }

// Run is only meaningful on Windows.
func Run(run func(ctx context.Context) error) error { return run(context.Background()) }

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", errors.New("systemctl was not found: this system does not use systemd; start the program from your init system instead")
		}
		if text != "" {
			return text, fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), text)
		}
		return text, fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return text, nil
}

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root: run it with sudo")
	}
	return nil
}

// Install writes the unit and enables it, so that it starts with the system.
func Install(c Config) error {
	if err := needRoot(); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl was not found: this system does not use systemd; start the program from your init system instead")
	}
	if err := os.WriteFile(unitPath, []byte(systemdUnit(c)), 0o644); err != nil {
		return err
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	_, err := systemctl("enable", unitName)
	return err
}

// Uninstall stops, disables and removes the unit.
func Uninstall() error {
	if err := needRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(unitPath); err != nil {
		return errors.New("the service is not installed")
	}
	_, _ = systemctl("disable", "--now", unitName)
	if err := os.Remove(unitPath); err != nil {
		return err
	}
	_, err := systemctl("daemon-reload")
	return err
}

// Start starts the installed service.
func Start() error {
	if err := needRoot(); err != nil {
		return err
	}
	_, err := systemctl("start", unitName)
	return err
}

// Stop stops the running service.
func Stop() error {
	if err := needRoot(); err != nil {
		return err
	}
	_, err := systemctl("stop", unitName)
	return err
}

// Status reports the state of the service and the command it runs.
func Status() (state, command string, err error) {
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return StateNotInstalled, "", nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "ExecStart="); ok {
			command = rest
		}
	}
	// "is-active" exits non-zero for everything but "active"; the word matters.
	out, _ := exec.Command("systemctl", "is-active", unitName).Output()
	switch word := strings.TrimSpace(string(out)); word {
	case "active":
		return StateRunning, command, nil
	case "inactive", "":
		return StateStopped, command, nil
	default:
		return word, command, nil
	}
}

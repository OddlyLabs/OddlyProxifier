//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const plistPath = "/Library/LaunchDaemons/" + launchLabel + ".plist"

// IsService is only meaningful on Windows.
func IsService() bool { return false }

// Run is only meaningful on Windows.
func Run(run func(ctx context.Context) error) error { return run(context.Background()) }

func launchctl(args ...string) (string, error) {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("launchctl %s: %s", strings.Join(args, " "), text)
		}
		return text, fmt.Errorf("launchctl %s: %w", strings.Join(args, " "), err)
	}
	return text, nil
}

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root: run it with sudo")
	}
	return nil
}

func loaded() bool {
	return exec.Command("launchctl", "print", "system/"+launchLabel).Run() == nil
}

// Install writes the launch daemon, which starts with the system.
func Install(c Config) error {
	if err := needRoot(); err != nil {
		return err
	}
	if loaded() {
		_, _ = launchctl("bootout", "system/"+launchLabel)
	}
	if err := os.WriteFile(plistPath, []byte(launchdPlist(c)), 0o644); err != nil {
		return err
	}
	// Loaded but not started: RunAtLoad starts it at the next boot, "service
	// start" starts it now.
	_, _ = launchctl("enable", "system/"+launchLabel)
	return nil
}

// Uninstall stops and removes the launch daemon.
func Uninstall() error {
	if err := needRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(plistPath); err != nil {
		return errors.New("the service is not installed")
	}
	if loaded() {
		_, _ = launchctl("bootout", "system/"+launchLabel)
	}
	return os.Remove(plistPath)
}

// Start starts the installed service.
func Start() error {
	if err := needRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(plistPath); err != nil {
		return errors.New("the service is not installed")
	}
	if loaded() {
		_, err := launchctl("kickstart", "system/"+launchLabel)
		return err
	}
	_, err := launchctl("bootstrap", "system", plistPath)
	return err
}

// Stop stops the running service.
func Stop() error {
	if err := needRoot(); err != nil {
		return err
	}
	if !loaded() {
		return nil
	}
	_, err := launchctl("bootout", "system/"+launchLabel)
	return err
}

// Status reports the state of the service and the command it runs.
func Status() (state, command string, err error) {
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return StateNotInstalled, "", nil
	}
	var words []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "<string>"); ok && strings.HasSuffix(rest, "</string>") {
			words = append(words, strings.TrimSuffix(rest, "</string>"))
		}
	}
	if len(words) > 2 {
		command = strings.Join(words[1:len(words)-1], " ") // without the label and the log path
	}
	out, err := exec.Command("launchctl", "print", "system/"+launchLabel).Output()
	if err != nil {
		return StateStopped, command, nil
	}
	if strings.Contains(string(out), "state = running") {
		return StateRunning, command, nil
	}
	return StateStopped, command, nil
}

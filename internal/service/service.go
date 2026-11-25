// Package service registers the engine with the system's service manager, so
// that it starts with the machine and runs with the rights interception needs:
// the Service Control Manager on Windows, systemd on Linux, launchd on macOS.
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Name is the name of the service.
const Name = "OddlyProxifier"

const (
	displayName = "OddlyProxifier"
	description = "Runs applications through SOCKS and HTTPS proxy servers."
	unitName    = "oddlyproxifier.service"
	launchLabel = "com.oddlyproxifier.engine"
)

// States reported by Status.
const (
	StateNotInstalled = "not installed"
	StateStopped      = "stopped"
	StateRunning      = "running"
)

// ErrUnsupported is returned where no service manager is known.
var ErrUnsupported = errors.New("services are not supported on this system")

// Config is what the service is started with.
type Config struct {
	Exe     string // absolute path of this program
	Profile string // absolute path of the profile
	API     string // listen address of the web interface; empty: the profile's
}

// NewConfig fills in the program's own path and makes the profile path
// absolute: a service does not run in the caller's directory, and not as the
// caller either.
func NewConfig(profile, api string) (Config, error) {
	exe, err := os.Executable()
	if err != nil {
		return Config{}, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return Config{}, err
	}
	if profile, err = filepath.Abs(profile); err != nil {
		return Config{}, err
	}
	return Config{Exe: exe, Profile: profile, API: api}, nil
}

// args are the arguments the service starts the engine with.
func (c Config) args() []string {
	a := []string{"run", "-profile", c.Profile}
	if c.API != "" {
		a = append(a, "-api", c.API)
	}
	return a
}

// systemdQuote quotes one word of an Exec line.
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
	return `"` + r.Replace(s) + `"`
}

// systemdUnit is the unit file for c.
func systemdUnit(c Config) string {
	words := []string{systemdQuote(c.Exe)}
	for _, a := range c.args() {
		words = append(words, systemdQuote(a))
	}
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
# Redirection rules of an engine that died must not outlive it.
ExecStopPost=%s cleanup
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, description, strings.Join(words, " "), systemdQuote(c.Exe))
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// launchdPlist is the launch daemon description for c.
func launchdPlist(c Config) string {
	var args strings.Builder
	for _, a := range append([]string{c.Exe}, c.args()...) {
		fmt.Fprintf(&args, "\t\t<string>%s</string>\n", xmlEscape(a))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>StandardErrorPath</key>
	<string>/var/log/oddlyproxifier.log</string>
</dict>
</plist>
`, launchLabel, args.String())
}

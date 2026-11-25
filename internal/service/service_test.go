package service

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	c := Config{Exe: "/opt/op/oddlyproxifier", Profile: "/etc/op/profile.json"}
	if got := strings.Join(c.args(), "|"); got != "run|-profile|/etc/op/profile.json" {
		t.Errorf("args: %s", got)
	}
	c.API = "127.0.0.1:9999"
	if got := strings.Join(c.args(), "|"); got != "run|-profile|/etc/op/profile.json|-api|127.0.0.1:9999" {
		t.Errorf("args: %s", got)
	}
}

func TestNewConfigMakesPathsAbsolute(t *testing.T) {
	c, err := NewConfig("profile.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(c.Profile, "profile.json") || c.Profile == "profile.json" || c.Exe == "" {
		t.Errorf("config: %+v", c)
	}
}

func TestSystemdUnit(t *testing.T) {
	u := systemdUnit(Config{Exe: "/opt/my apps/odd$ly", Profile: `/home/a "b"/100%.json`, API: "[::1]:9090"})
	want := `ExecStart="/opt/my apps/odd$$ly" "run" "-profile" "/home/a \"b\"/100%%.json" "-api" "[::1]:9090"` + "\n"
	if !strings.Contains(u, want) {
		t.Errorf("unit:\n%s", u)
	}
	for _, line := range []string{
		`ExecStopPost="/opt/my apps/odd$$ly" cleanup`, "Restart=on-failure", "WantedBy=multi-user.target", "[Unit]", "[Service]", "[Install]",
	} {
		if !strings.Contains(u, line+"\n") {
			t.Errorf("the unit lacks %q", line)
		}
	}
}

func TestLaunchdPlist(t *testing.T) {
	p := launchdPlist(Config{Exe: "/Applications/Odd & Co/oddlyproxifier", Profile: "/Users/a<b>/profile.json"})
	// It must be well-formed XML with the arguments intact.
	var doc struct {
		Strings []string `xml:"dict>array>string"`
		Keys    []string `xml:"dict>key"`
	}
	if err := xml.Unmarshal([]byte(p), &doc); err != nil {
		t.Fatalf("%v\n%s", err, p)
	}
	if got := strings.Join(doc.Strings, "|"); got != "/Applications/Odd & Co/oddlyproxifier|run|-profile|/Users/a<b>/profile.json" {
		t.Errorf("arguments: %s", got)
	}
	if got := strings.Join(doc.Keys, " "); got != "Label ProgramArguments RunAtLoad KeepAlive ThrottleInterval StandardErrorPath" {
		t.Errorf("keys: %s", got)
	}
}

func TestStatusDoesNotNeedRights(t *testing.T) {
	state, _, err := Status()
	if err != nil {
		t.Skipf("no service manager here: %v", err)
	}
	if state == "" {
		t.Error("empty state")
	}
}

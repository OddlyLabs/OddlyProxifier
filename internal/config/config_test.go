package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	p := Default()
	if err := p.Validate(); err != nil {
		t.Fatalf("the default profile does not validate: %v", err)
	}
	if !p.Options.Intercept || p.Options.Inbound == "" || !p.DNS.Sniff {
		t.Errorf("unexpected defaults: %+v %+v", p.Options, p.DNS)
	}
	if p.Default.Type != ActionDirect {
		t.Errorf("the default action is %q; a fresh install must not proxy anything", p.Default.Type)
	}
	if len(p.Options.APIToken) < 16 {
		t.Errorf("weak API token %q", p.Options.APIToken)
	}
	if Default().Options.APIToken == p.Options.APIToken {
		t.Error("two default profiles share one API token")
	}
}

func TestNormalizeFillsIn(t *testing.T) {
	p := &Profile{
		Proxies: []Proxy{{Type: " SOCKS5 ", Host: " 10.0.0.1 ", Port: 1080}},
		Chains:  []Chain{{Name: "c"}},
		Rules:   []Rule{{Name: "r"}},
	}
	p.Normalize()
	x := p.Proxies[0]
	if x.Type != TypeSOCKS5 || x.Host != "10.0.0.1" || x.ID == "" || x.Name != "10.0.0.1:1080" {
		t.Errorf("proxy not normalized: %+v", x)
	}
	if c := p.Chains[0]; c.ID == "" || c.Type != ChainSimple || c.Proxies == nil {
		t.Errorf("chain not normalized: %+v", c)
	}
	if r := p.Rules[0]; r.ID == "" || r.Action.Type != ActionDirect {
		t.Errorf("rule not normalized: %+v", r)
	}
	if p.Version != CurrentVersion || p.Default.Type != ActionDirect || p.DNS.Mode != DNSAuto {
		t.Errorf("profile not normalized: %+v", p)
	}
	o := p.Options
	if o.TransparentPort != 37080 || o.API != "127.0.0.1:9090" || o.APIToken == "" || o.ConnectTimeout != 15 {
		t.Errorf("options not normalized: %+v", o)
	}
	// Normalizing twice changes nothing, so a saved profile stays stable.
	before, _ := json.Marshal(p)
	p.Normalize()
	after, _ := json.Marshal(p)
	if string(before) != string(after) {
		t.Error("Normalize is not idempotent")
	}
}

func valid() *Profile {
	p := &Profile{
		Proxies: []Proxy{
			{ID: "a", Name: "A", Type: TypeSOCKS5, Host: "10.0.0.1", Port: 1080},
			{ID: "b", Name: "B", Type: TypeHTTPS, Host: "proxy.example", Port: 443},
		},
		Chains: []Chain{{ID: "c", Name: "C", Type: ChainSimple, Proxies: []string{"a", "b"}}},
		Rules: []Rule{
			{ID: "r1", Name: "one", Enabled: true, Action: Action{Type: ActionProxy, Target: "a"}},
			{ID: "r2", Name: "two", Enabled: true, Action: Action{Type: ActionChain, Target: "c"}},
		},
		Default: Action{Type: ActionBlock},
	}
	p.Normalize()
	return p
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	cases := []struct {
		name string
		edit func(*Profile)
		want string // part of the error
	}{
		{"duplicate proxy id", func(p *Profile) { p.Proxies[1].ID = "a" }, "duplicate id"},
		{"unknown proxy type", func(p *Profile) { p.Proxies[0].Type = "socks6" }, "unknown type"},
		{"empty host", func(p *Profile) { p.Proxies[0].Host = "" }, "host is empty"},
		{"port zero", func(p *Profile) { p.Proxies[0].Port = 0 }, "bad port"},
		{"port too large", func(p *Profile) { p.Proxies[0].Port = 70000 }, "bad port"},
		{"long user name", func(p *Profile) { p.Proxies[0].Username = strings.Repeat("u", 256) }, "too long"},
		{"duplicate chain id", func(p *Profile) { p.Chains = append(p.Chains, p.Chains[0]) }, "duplicate id"},
		{"unknown chain type", func(p *Profile) { p.Chains[0].Type = "ring" }, "unknown type"},
		{"empty chain", func(p *Profile) { p.Chains[0].Proxies = nil }, "no proxies"},
		{"chain refers to a missing proxy", func(p *Profile) { p.Chains[0].Proxies = []string{"a", "zz"} }, "unknown proxy"},
		{"rule refers to a missing proxy", func(p *Profile) { p.Rules[0].Action.Target = "zz" }, "unknown proxy"},
		{"rule refers to a missing chain", func(p *Profile) { p.Rules[1].Action.Target = "zz" }, "unknown chain"},
		{"proxy id used as chain", func(p *Profile) { p.Rules[1].Action.Target = "a" }, "unknown chain"},
		{"unknown action", func(p *Profile) { p.Rules[0].Action.Type = "drop" }, "unknown action"},
		{"default refers to a missing proxy", func(p *Profile) { p.Default = Action{Type: ActionProxy, Target: "zz"} }, "default rule"},
		{"unknown DNS mode", func(p *Profile) { p.DNS.Mode = "magic" }, "unknown mode"},
		{"transparent port", func(p *Profile) { p.Options.TransparentPort = 65536 }, "transparent_port"},
		{"target port", func(p *Profile) { p.Options.TargetPort = -1 }, "target_port"},
		{"inbound without a port", func(p *Profile) { p.Options.Inbound = "127.0.0.1" }, "not host:port"},
		{"API without a port", func(p *Profile) { p.Options.API = "localhost" }, "not host:port"},
		{"fake range is IPv6", func(p *Profile) { p.DNS.Fake.Range = "fd00::/8" }, "fake range"},
		{"fake range too small", func(p *Profile) { p.DNS.Fake.Range = "198.18.0.0/31" }, "fake range"},
	}
	for _, c := range cases {
		p := valid()
		c.edit(p)
		err := p.Validate()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestCloneIsDeep(t *testing.T) {
	p := valid()
	p.Rules[0].Apps = []string{"a.exe"}
	c := p.Clone()
	if !reflect.DeepEqual(p, c) {
		t.Fatalf("clone differs:\n%+v\n%+v", p, c)
	}
	c.Proxies[0].Host = "changed"
	c.Chains[0].Proxies[0] = "changed"
	c.Rules[0].Apps[0] = "changed"
	if p.Proxies[0].Host == "changed" || p.Chains[0].Proxies[0] == "changed" || p.Rules[0].Apps[0] == "changed" {
		t.Error("the clone shares memory with the original")
	}
}

func TestLoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "profile.json")

	// No file yet: defaults.
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load of a missing file: %v", err)
	}
	if len(p.Rules) != 1 || p.Rules[0].ID != "local" {
		t.Errorf("a missing file should give the default profile, got %+v", p.Rules)
	}

	want := valid()
	want.Proxies[0].Password = "s3cret"
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the profile:\n got %+v\nwant %+v", got, want)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind")
	}
	// Saving over an existing file works as well.
	want.Default = Action{Type: ActionDirect}
	if err := Save(path, want); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	if got, _ := Load(path); got == nil || got.Default.Type != ActionDirect {
		t.Error("the second Save did not replace the file")
	}
}

func TestLoadRejectsBrokenFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, err := Load(write("syntax.json", "{not json")); err == nil {
		t.Error("broken JSON was accepted")
	}
	bad := `{"rules":[{"name":"r","enabled":true,"action":{"type":"proxy","target":"nope"}}]}`
	if _, err := Load(write("ref.json", bad)); err == nil || !strings.Contains(err.Error(), "unknown proxy") {
		t.Errorf("dangling reference: err = %v", err)
	}
	// A minimal hand-written file is completed.
	p, err := Load(write("min.json", `{"proxies":[{"type":"socks5","host":"10.0.0.1","port":1080}]}`))
	if err != nil {
		t.Fatalf("minimal profile: %v", err)
	}
	if p.Proxies[0].ID == "" || p.Options.APIToken == "" || p.Default.Type != ActionDirect {
		t.Errorf("minimal profile was not completed: %+v", p)
	}
}

// A hand-written file that leaves sections out keeps the defaults for them.
func TestLoadPartialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	text := `{"proxies":[{"id":"a","type":"socks5","host":"192.0.2.1","port":1080}],
		"default":{"type":"proxy","target":"a"},
		"options":{"intercept":true,"idle_timeout":7}}`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	def := Default()
	if !p.DNS.Sniff || p.DNS.Mode != def.DNS.Mode {
		t.Errorf("dns: %+v", p.DNS)
	}
	if !p.Options.Intercept || p.Options.IdleTimeout != 7 || p.Options.TransparentPort != def.Options.TransparentPort ||
		p.Options.Inbound != def.Options.Inbound || p.Options.API != def.Options.API {
		t.Errorf("options: %+v", p.Options)
	}
	if len(p.Rules) != 0 || len(p.Proxies) != 1 || p.Default.Target != "a" {
		t.Errorf("lists: %d rules, %d proxies, default %+v", len(p.Rules), len(p.Proxies), p.Default)
	}
}

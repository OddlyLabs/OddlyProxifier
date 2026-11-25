package profiles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"oddlyproxifier/internal/config"
)

func TestCheckName(t *testing.T) {
	for _, good := range []string{"Work", "家里", "a b", "v1.2", strings.Repeat("x", 64)} {
		if err := CheckName(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	for _, bad := range []string{"", " a", "a ", ".hidden", "end.", "a/b", `a\b`, "a:b", "..", "what?", "tab\there",
		"CON", "nul.txt", "com1", strings.Repeat("x", 65)} {
		if CheckName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func sample() *config.Profile {
	p := config.Default()
	p.Proxies = []config.Proxy{{ID: "a", Name: "A", Type: config.TypeSOCKS5, Host: "10.0.0.1", Port: 1080, Username: "u", Password: "secret"}}
	p.Chains = []config.Chain{{ID: "c", Name: "C", Type: config.ChainFailover, Proxies: []string{"a"}}}
	p.Default = config.Action{Type: config.ActionChain, Target: "c"}
	p.DNS.LocalNames = []string{"*.lan"}
	p.Options.APIToken = "token-of-this-machine"
	p.Options.Inbound = "127.0.0.1:7777"
	return p
}

func TestStore(t *testing.T) {
	if For("") != nil {
		t.Error("a store without a profile path")
	}
	dir := t.TempDir()
	s := For(filepath.Join(dir, "profile.json"))
	if s.Dir() != filepath.Join(dir, "profiles") {
		t.Errorf("Dir() = %s", s.Dir())
	}
	if list, err := s.List(); err != nil || len(list) != 0 {
		t.Fatalf("empty store: %v %v", list, err)
	}
	p := sample()
	for _, name := range []string{"work", "Home"} {
		if err := s.Save(name, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save("a/b", p); err == nil {
		t.Error("a path was accepted as a name")
	}
	// Other files in the directory are neither listed nor touched.
	_ = os.WriteFile(filepath.Join(s.Dir(), "notes.txt"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(s.Dir(), "broken.json"), []byte("{"), 0o600)
	list, err := s.List()
	if err != nil || len(list) != 2 || list[0].Name != "Home" || list[1].Name != "work" {
		t.Fatalf("list: %+v %v", list, err)
	}
	if i := list[0]; i.Proxies != 1 || i.Chains != 1 || i.Rules != len(p.Rules) || i.Modified == 0 {
		t.Errorf("info: %+v", i)
	}

	raw, _ := os.ReadFile(filepath.Join(s.Dir(), "work.json"))
	if strings.Contains(string(raw), "token-of-this-machine") || strings.Contains(string(raw), "7777") || !strings.Contains(string(raw), "secret") {
		t.Errorf("stored file:\n%s", raw)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(s.Dir(), "work.json")); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", fi.Mode())
		}
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), "work.json.tmp")); err == nil {
		t.Error("the temporary file was left behind")
	}

	got, err := s.Load("work")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "work" || got.Proxies[0].Password != "secret" || got.Default.Target != "c" || got.DNS.LocalNames[0] != "*.lan" {
		t.Errorf("loaded: %+v", got)
	}
	if _, err := s.Load("gone"); err == nil {
		t.Error("loaded a profile that does not exist")
	}
	if _, err := s.Load("../profile"); err == nil {
		t.Error("loaded outside the store")
	}
	if err := s.Delete("work"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("work"); err == nil {
		t.Error("deleted twice")
	}
	if list, _ = s.List(); len(list) != 1 {
		t.Errorf("after delete: %+v", list)
	}
}

func TestApplyKeepsMachineSettings(t *testing.T) {
	cur := config.Default()
	cur.Options.APIToken, cur.Options.Inbound = "mine", "127.0.0.1:1"
	cur.DNS.Fake.Listen, cur.DNS.Fake.Upstream = "127.0.0.1:5353", "9.9.9.9:53"
	saved := sample()
	saved.DNS.Mode = config.DNSLocal
	saved.DNS.Fake.Listen = "127.0.0.9:53"
	out := Apply(cur, saved, "Work")
	if out.Name != "Work" || len(out.Proxies) != 1 || out.Default.Target != "c" || out.DNS.Mode != config.DNSLocal || out.DNS.LocalNames[0] != "*.lan" {
		t.Errorf("routing part: %+v", out)
	}
	if out.Options.APIToken != "mine" || out.Options.Inbound != "127.0.0.1:1" || out.DNS.Fake.Listen != "127.0.0.1:5353" || out.DNS.Fake.Upstream != "9.9.9.9:53" {
		t.Errorf("machine part: %+v %+v", out.Options, out.DNS.Fake)
	}
	// Nothing is shared with the inputs.
	out.Proxies[0].Host = "changed"
	if saved.Proxies[0].Host == "changed" || len(cur.Proxies) != 0 {
		t.Error("Apply shares memory with its arguments")
	}
	if err := out.Validate(); err != nil {
		t.Error(err)
	}
}

func TestExport(t *testing.T) {
	p := sample()
	for _, with := range []bool{false, true} {
		data, err := Export(p, "Shared", with)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["options"]; ok || string(m["name"]) != `"Shared"` {
			t.Errorf("keys: %v", m)
		}
		if strings.Contains(string(data), "secret") != with {
			t.Errorf("passwords=%v:\n%s", with, data)
		}
	}
	if p.Proxies[0].Password != "secret" || p.Name != "" {
		t.Error("Export changed its argument")
	}
}

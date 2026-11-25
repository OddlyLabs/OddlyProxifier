// Package profiles keeps named profiles next to the active one, so that a
// set of proxies and rules can be saved, switched and shared.
package profiles

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"oddlyproxifier/internal/config"
)

// Store is a directory of <name>.json files.
type Store struct{ dir string }

// For returns the store that belongs to the active profile at path:
// the directory "profiles" beside it.
func For(path string) *Store {
	if path == "" {
		return nil
	}
	return &Store{dir: filepath.Join(filepath.Dir(path), "profiles")}
}

// Dir is where the profiles are kept.
func (s *Store) Dir() string { return s.dir }

// Info describes one saved profile.
type Info struct {
	Name     string `json:"name"`
	Modified int64  `json:"modified"` // unix seconds
	Proxies  int    `json:"proxies"`
	Chains   int    `json:"chains"`
	Rules    int    `json:"rules"`
}

// CheckName accepts names that are safe as a file name on every system.
func CheckName(name string) error {
	if name == "" || len(name) > 64 {
		return errors.New("the name must have 1 to 64 characters")
	}
	if strings.TrimSpace(name) != name || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return errors.New("the name must not start or end with a space or a dot")
	}
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return fmt.Errorf("the name must not contain %q", r)
		}
	}
	switch strings.ToUpper(strings.SplitN(name, ".", 2)[0]) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3":
		return errors.New("that name is reserved by Windows")
	}
	return nil
}

func (s *Store) file(name string) string { return filepath.Join(s.dir, name+".json") }

// List returns the saved profiles, sorted by name.
func (s *Store) List() ([]Info, error) {
	out := []Info{}
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() || CheckName(name) != nil {
			continue
		}
		p, err := s.Load(name)
		if err != nil {
			continue // not a profile; leave the file alone
		}
		info := Info{Name: name, Proxies: len(p.Proxies), Chains: len(p.Chains), Rules: len(p.Rules)}
		if fi, err := e.Info(); err == nil {
			info.Modified = fi.ModTime().Unix()
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// Load reads one saved profile.
func (s *Store) Load(name string) (*config.Profile, error) {
	if err := CheckName(name); err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.file(name)); err != nil {
		return nil, fmt.Errorf("there is no saved profile %q", name)
	}
	return config.Load(s.file(name))
}

// Save stores the routing part of p under name. Settings that belong to this
// machine and installation (ports, the access token, the log file) are left out.
func (s *Store) Save(name string, p *config.Profile) error {
	if err := CheckName(name); err != nil {
		return err
	}
	data, err := Export(p, name, true)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	// Proxy passwords are inside: owner-only, written atomically.
	tmp := s.file(name) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.file(name))
}

// Delete removes a saved profile.
func (s *Store) Delete(name string) error {
	if err := CheckName(name); err != nil {
		return err
	}
	err := os.Remove(s.file(name))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("there is no saved profile %q", name)
	}
	return err
}

// Apply returns cur with the routing part replaced by that of saved.
func Apply(cur, saved *config.Profile, name string) *config.Profile {
	out := cur.Clone()
	s := saved.Clone()
	out.Name = name
	out.Proxies, out.Chains, out.Rules, out.Default = s.Proxies, s.Chains, s.Rules, s.Default
	fake := out.DNS.Fake
	out.DNS = s.DNS
	// Where the fake DNS server listens is a property of this machine.
	out.DNS.Fake.Listen, out.DNS.Fake.Upstream = fake.Listen, fake.Upstream
	return out
}

// Export renders what a profile means on any machine - proxies, chains,
// rules, the default action and name resolution - as indented JSON.
func Export(p *config.Profile, name string, withPasswords bool) ([]byte, error) {
	c := p.Clone()
	c.Name = name
	if !withPasswords {
		for i := range c.Proxies {
			c.Proxies[i].Password = ""
		}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "options") // ports, token, log file: this installation's own
	return json.MarshalIndent(m, "", "  ")
}

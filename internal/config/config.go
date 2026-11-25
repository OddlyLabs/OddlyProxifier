// Package config defines the on-disk profile: proxy servers, chains, rules
// and engine options.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const CurrentVersion = 1

// Proxy server types.
const (
	TypeSOCKS5  = "socks5"
	TypeSOCKS4  = "socks4"
	TypeSOCKS4A = "socks4a"
	TypeHTTP    = "http"  // HTTP CONNECT over plain TCP
	TypeHTTPS   = "https" // HTTP CONNECT over TLS
)

// Rule action types.
const (
	ActionDirect = "direct"
	ActionBlock  = "block"
	ActionProxy  = "proxy"
	ActionChain  = "chain"
)

// Chain types.
const (
	ChainSimple   = "chain"    // hop1 -> hop2 -> ... -> target
	ChainFailover = "failover" // first working proxy wins
	ChainBalance  = "balance"  // round-robin, with failover
)

// DNS modes.
const (
	DNSAuto   = "auto"   // hostname goes to the proxy when it is known
	DNSRemote = "remote" // same as auto (kept for clarity in the UI)
	DNSLocal  = "local"  // always resolve locally and hand the proxy an IP
)

type Proxy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	TLSInsecure   bool   `json:"tls_insecure,omitempty"`
}

type Chain struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Proxies []string `json:"proxies"`
}

type Action struct {
	Type   string `json:"type"`
	Target string `json:"target,omitempty"` // proxy or chain ID
}

type Rule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	Apps    []string `json:"apps,omitempty"`  // "chrome.exe", "*\\Steam\\*", empty = any
	Hosts   []string `json:"hosts,omitempty"` // "*.example.com", "10.0.0.0/8", "1.1.1.1-1.1.1.9"
	Ports   string   `json:"ports,omitempty"` // "80,443,8000-9000", empty = any
	Action  Action   `json:"action"`
}

type FakeDNS struct {
	Enabled  bool   `json:"enabled"`
	Listen   string `json:"listen"`
	Range    string `json:"range"`
	Upstream string `json:"upstream"`
}

type DNS struct {
	Mode  string  `json:"mode"`
	Sniff bool    `json:"sniff"` // recover hostnames from TLS SNI / HTTP Host
	Fake  FakeDNS `json:"fake"`
	// LocalNames are host patterns that are always resolved on this machine,
	// whatever Mode says ("*.corp.example", "printer").
	LocalNames []string `json:"local_names"`
}

type Options struct {
	Intercept       bool   `json:"intercept"`        // system-wide transparent interception
	TransparentPort int    `json:"transparent_port"` // broker port redirected flows land on
	IPv6            bool   `json:"ipv6"`             // also intercept IPv6
	TargetPort      int    `json:"target_port"`      // debug: only intercept this dst port (0 = all)
	HandleDirect    bool   `json:"handle_direct"`    // also route connections that can only go direct through the engine
	BlockQUIC       bool   `json:"block_quic"`       // reject UDP/443 of intercepted apps so they fall back to TCP
	Inbound         string `json:"inbound"`          // mixed SOCKS5/SOCKS4/HTTP listener, "" = off
	API             string `json:"api"`              // web UI / API listener
	APIToken        string `json:"api_token"`
	ConnectTimeout  int    `json:"connect_timeout"` // seconds
	IdleTimeout     int    `json:"idle_timeout"`    // seconds without traffic before a connection is dropped, 0 = never
	UDP             bool   `json:"udp"`             // SOCKS5 UDP ASSOCIATE on the inbound listener
	LogFile         string `json:"log_file"`        // append the log to this file, "" = off
	LogLevel        string `json:"log_level"`       // least severe level written to the file
}

type Profile struct {
	Version int     `json:"version"`
	Name    string  `json:"name,omitempty"` // the saved profile this one was loaded from
	Proxies []Proxy `json:"proxies"`
	Chains  []Chain `json:"chains"`
	Rules   []Rule  `json:"rules"`
	Default Action  `json:"default"`
	DNS     DNS     `json:"dns"`
	Options Options `json:"options"`
}

// Default returns a profile that intercepts nothing harmful: everything goes
// direct until the user adds a proxy and a rule.
func Default() *Profile {
	p := &Profile{
		Version: CurrentVersion,
		Proxies: []Proxy{},
		Chains:  []Chain{},
		Rules: []Rule{{
			ID: "local", Name: "Localhost / LAN", Enabled: true,
			Hosts: []string{
				"localhost", "127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12",
				"192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7",
			},
			Action: Action{Type: ActionDirect},
		}},
		Default: Action{Type: ActionDirect},
	}
	p.Normalize()
	p.DNS.Sniff = true
	p.Options.Intercept = true
	p.Options.IPv6 = true
	p.Options.BlockQUIC = true
	p.Options.Inbound = "127.0.0.1:1080"
	p.Options.UDP = true
	return p
}

// Normalize fills in zero values so that the rest of the code can rely on them.
func (p *Profile) Normalize() {
	if p.Version == 0 {
		p.Version = CurrentVersion
	}
	if p.Proxies == nil {
		p.Proxies = []Proxy{}
	}
	if p.Chains == nil {
		p.Chains = []Chain{}
	}
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	if p.Default.Type == "" {
		p.Default.Type = ActionDirect
	}
	for i := range p.Proxies {
		x := &p.Proxies[i]
		x.Type = strings.ToLower(strings.TrimSpace(x.Type))
		x.Host = strings.TrimSpace(x.Host)
		if x.ID == "" {
			x.ID = NewID()
		}
		if x.Name == "" {
			x.Name = fmt.Sprintf("%s:%d", x.Host, x.Port)
		}
	}
	for i := range p.Chains {
		x := &p.Chains[i]
		if x.ID == "" {
			x.ID = NewID()
		}
		if x.Type == "" {
			x.Type = ChainSimple
		}
		if x.Proxies == nil {
			x.Proxies = []string{}
		}
	}
	for i := range p.Rules {
		x := &p.Rules[i]
		if x.ID == "" {
			x.ID = NewID()
		}
		if x.Action.Type == "" {
			x.Action.Type = ActionDirect
		}
	}
	if p.DNS.Mode == "" {
		p.DNS.Mode = DNSAuto
	}
	if p.DNS.LocalNames == nil {
		p.DNS.LocalNames = []string{}
	}
	if p.DNS.Fake.Listen == "" {
		p.DNS.Fake.Listen = "127.0.0.1:53"
	}
	if p.DNS.Fake.Range == "" {
		p.DNS.Fake.Range = "198.18.0.0/15"
	}
	if p.DNS.Fake.Upstream == "" {
		p.DNS.Fake.Upstream = "223.5.5.5:53"
	}
	o := &p.Options
	if o.TransparentPort == 0 {
		o.TransparentPort = 37080
	}
	if o.API == "" {
		o.API = "127.0.0.1:9090"
	}
	if o.APIToken == "" {
		o.APIToken = NewID() + NewID()
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 15
	}
	if o.IdleTimeout < 0 {
		o.IdleTimeout = 0
	}
	o.LogFile = strings.TrimSpace(o.LogFile)
	if o.LogLevel == "" {
		o.LogLevel = "info"
	}
}

// Validate checks structure and cross references. Pattern syntax (hosts,
// ports) is checked by rules.Compile.
func (p *Profile) Validate() error {
	ids := map[string]bool{}
	for _, x := range p.Proxies {
		if ids[x.ID] {
			return fmt.Errorf("proxy %q: duplicate id", x.Name)
		}
		ids[x.ID] = true
		switch x.Type {
		case TypeSOCKS5, TypeSOCKS4, TypeSOCKS4A, TypeHTTP, TypeHTTPS:
		default:
			return fmt.Errorf("proxy %q: unknown type %q", x.Name, x.Type)
		}
		if x.Host == "" {
			return fmt.Errorf("proxy %q: host is empty", x.Name)
		}
		if x.Port < 1 || x.Port > 65535 {
			return fmt.Errorf("proxy %q: bad port %d", x.Name, x.Port)
		}
		if len(x.Username) > 255 || len(x.Password) > 255 {
			return fmt.Errorf("proxy %q: username/password too long", x.Name)
		}
	}
	cids := map[string]bool{}
	for _, c := range p.Chains {
		if cids[c.ID] {
			return fmt.Errorf("chain %q: duplicate id", c.Name)
		}
		cids[c.ID] = true
		switch c.Type {
		case ChainSimple, ChainFailover, ChainBalance:
		default:
			return fmt.Errorf("chain %q: unknown type %q", c.Name, c.Type)
		}
		if len(c.Proxies) == 0 {
			return fmt.Errorf("chain %q: no proxies", c.Name)
		}
		for _, id := range c.Proxies {
			if !ids[id] {
				return fmt.Errorf("chain %q: unknown proxy %q", c.Name, id)
			}
		}
	}
	check := func(where string, a Action) error {
		switch a.Type {
		case ActionDirect, ActionBlock:
		case ActionProxy:
			if !ids[a.Target] {
				return fmt.Errorf("%s: unknown proxy %q", where, a.Target)
			}
		case ActionChain:
			if !cids[a.Target] {
				return fmt.Errorf("%s: unknown chain %q", where, a.Target)
			}
		default:
			return fmt.Errorf("%s: unknown action %q", where, a.Type)
		}
		return nil
	}
	for _, r := range p.Rules {
		if err := check(fmt.Sprintf("rule %q", r.Name), r.Action); err != nil {
			return err
		}
	}
	if err := check("default rule", p.Default); err != nil {
		return err
	}
	switch p.DNS.Mode {
	case DNSAuto, DNSRemote, DNSLocal:
	default:
		return fmt.Errorf("dns: unknown mode %q", p.DNS.Mode)
	}
	switch p.Options.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("options: unknown log_level %q", p.Options.LogLevel)
	}
	if len(p.Name) > 64 {
		return errors.New("profile name too long")
	}
	if p.Options.TransparentPort < 1 || p.Options.TransparentPort > 65535 {
		return errors.New("options: bad transparent_port")
	}
	if p.Options.TargetPort < 0 || p.Options.TargetPort > 65535 {
		return errors.New("options: bad target_port")
	}
	for name, addr := range map[string]string{
		"options: inbound": p.Options.Inbound, "options: api": p.Options.API,
		"dns: fake listen": p.DNS.Fake.Listen, "dns: fake upstream": p.DNS.Fake.Upstream,
	} {
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s: %q is not host:port", name, addr)
		}
	}
	if pfx, err := netip.ParsePrefix(p.DNS.Fake.Range); err != nil || !pfx.Addr().Is4() || pfx.Bits() < 8 || pfx.Bits() > 30 {
		return errors.New("dns: fake range must be an IPv4 network between /8 and /30")
	}
	return nil
}

// Clone returns a deep copy.
func (p *Profile) Clone() *Profile {
	data, _ := json.Marshal(p)
	c := &Profile{}
	_ = json.Unmarshal(data, c)
	c.Normalize()
	return c
}

func NewID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// DefaultPath is <user config dir>/OddlyProxifier/profile.json.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "OddlyProxifier", "profile.json")
}

// Load reads a profile; a missing file yields the default profile.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	// Settings a hand-written file leaves out keep their defaults; the
	// lists are taken from the file alone.
	p := Default()
	p.Proxies, p.Chains, p.Rules = nil, nil, nil
	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Save writes the profile atomically. It holds proxy passwords, so the file
// is created owner-only.
func Save(path string, p *Profile) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

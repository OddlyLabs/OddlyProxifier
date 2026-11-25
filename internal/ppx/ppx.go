// Package ppx reads Proxifier profiles (.ppx, XML) and turns them into
// OddlyProxifier profiles.
package ppx

import (
	"encoding/xml"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"oddlyproxifier/internal/config"
)

type xmlProfile struct {
	XMLName xml.Name `xml:"ProxifierProfile"`
	Options struct {
		Resolve struct {
			AutoModeDetection struct {
				Enabled string `xml:"enabled,attr"`
			} `xml:"AutoModeDetection"`
			ViaProxy struct {
				Enabled string `xml:"enabled,attr"`
			} `xml:"ViaProxy"`
			ExclusionList string `xml:"ExclusionList"`
		} `xml:"Resolve"`
	} `xml:"Options"`
	Proxies []struct {
		ID      string `xml:"id,attr"`
		Type    string `xml:"type,attr"`
		Label   string `xml:"Label"`
		Address string `xml:"Address"`
		Port    string `xml:"Port"`
		Auth    struct {
			Enabled  string `xml:"enabled,attr"`
			Username string `xml:"Username"`
			Password string `xml:"Password"`
		} `xml:"Authentication"`
	} `xml:"ProxyList>Proxy"`
	Chains []struct {
		ID      string `xml:"id,attr"`
		Type    string `xml:"type,attr"`
		Name    string `xml:"Name"`
		Proxies []struct {
			Enabled string `xml:"enabled,attr"`
			ID      string `xml:",chardata"`
		} `xml:"Proxy"`
	} `xml:"ChainList>Chain"`
	Rules []struct {
		Enabled      string `xml:"enabled,attr"`
		Name         string `xml:"Name"`
		Applications string `xml:"Applications"`
		Targets      string `xml:"Targets"`
		Ports        string `xml:"Ports"`
		Action       struct {
			Type string `xml:"type,attr"`
			ID   string `xml:",chardata"`
		} `xml:"Action"`
	} `xml:"RuleList>Rule"`
}

// Looks reports whether data seems to be a Proxifier profile.
func Looks(data []byte) bool {
	head := data
	if len(head) > 2048 {
		head = head[:2048]
	}
	return strings.Contains(string(head), "<ProxifierProfile")
}

func on(attr string) bool { return attr == "" || strings.EqualFold(attr, "true") }

// Import converts a Proxifier profile. Things that have no counterpart are
// reported as notes rather than failing the import.
func Import(data []byte) (*config.Profile, []string, error) {
	var x xmlProfile
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, nil, fmt.Errorf("not a Proxifier profile: %w", err)
	}
	var notes []string
	note := func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }

	p := &config.Profile{Version: config.CurrentVersion, Default: config.Action{Type: config.ActionDirect}}
	p.DNS.Sniff = true
	p.DNS.Mode = config.DNSAuto
	if !on(x.Options.Resolve.AutoModeDetection.Enabled) && !strings.EqualFold(x.Options.Resolve.ViaProxy.Enabled, "true") {
		p.DNS.Mode = config.DNSLocal
	}
	for _, name := range split(x.Options.Resolve.ExclusionList) {
		if strings.Contains(name, "%") {
			continue // %ComputerName% and friends: single-label names resolve locally anyway
		}
		p.DNS.LocalNames = append(p.DNS.LocalNames, name)
	}

	proxyID := map[string]string{}
	for _, px := range x.Proxies {
		typ := ""
		switch strings.ToUpper(strings.TrimSpace(px.Type)) {
		case "SOCKS5":
			typ = config.TypeSOCKS5
		case "SOCKS4":
			typ = config.TypeSOCKS4A
		case "HTTPS", "HTTP":
			// Proxifier's "HTTPS" is an HTTP proxy that supports CONNECT.
			typ = config.TypeHTTP
		default:
			note("proxy %s:%s skipped: type %q is not supported", px.Address, px.Port, px.Type)
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(px.Port))
		if err != nil || port < 1 || port > 65535 {
			note("proxy %s skipped: bad port %q", px.Address, px.Port)
			continue
		}
		out := config.Proxy{
			ID: config.NewID(), Type: typ, Host: strings.TrimSpace(px.Address), Port: port,
			Name: strings.TrimSpace(px.Label),
		}
		if out.Name == "" {
			out.Name = fmt.Sprintf("%s:%d", out.Host, port)
		}
		if strings.EqualFold(px.Auth.Enabled, "true") {
			out.Username = px.Auth.Username
			if px.Auth.Password != "" {
				note("proxy %q: the password is stored encrypted by Proxifier and was not imported; enter it again", out.Name)
			}
		}
		proxyID[strings.TrimSpace(px.ID)] = out.ID
		p.Proxies = append(p.Proxies, out)
	}

	chainID := map[string]string{}
	for _, ch := range x.Chains {
		out := config.Chain{ID: config.NewID(), Name: strings.TrimSpace(ch.Name), Type: config.ChainSimple}
		switch strings.ToLower(strings.TrimSpace(ch.Type)) {
		case "redundancy":
			out.Type = config.ChainFailover
		case "load_balancing", "loadbalancing":
			out.Type = config.ChainBalance
		}
		for _, m := range ch.Proxies {
			id, ok := proxyID[strings.TrimSpace(m.ID)]
			if !ok || !on(m.Enabled) {
				continue
			}
			out.Proxies = append(out.Proxies, id)
		}
		if out.Name == "" {
			out.Name = "Chain " + strings.TrimSpace(ch.ID)
		}
		if len(out.Proxies) == 0 {
			note("chain %q skipped: none of its proxies could be imported", out.Name)
			continue
		}
		chainID[strings.TrimSpace(ch.ID)] = out.ID
		p.Chains = append(p.Chains, out)
	}

	action := func(rule, typ, id string) (config.Action, bool) {
		id = strings.TrimSpace(id)
		switch strings.ToLower(strings.TrimSpace(typ)) {
		case "direct":
			return config.Action{Type: config.ActionDirect}, true
		case "block":
			return config.Action{Type: config.ActionBlock}, true
		case "proxy":
			if t, ok := proxyID[id]; ok {
				return config.Action{Type: config.ActionProxy, Target: t}, true
			}
			// Proxifier uses the same action type for chains.
			if t, ok := chainID[id]; ok {
				return config.Action{Type: config.ActionChain, Target: t}, true
			}
		case "chain":
			if t, ok := chainID[id]; ok {
				return config.Action{Type: config.ActionChain, Target: t}, true
			}
		}
		note("rule %q skipped: its proxy or chain could not be imported", rule)
		return config.Action{}, false
	}

	for i, r := range x.Rules {
		name := strings.TrimSpace(r.Name)
		apps, hosts := split(r.Applications), targets(split(r.Targets))
		ports := strings.Join(split(r.Ports), ",")
		a, ok := action(name, r.Action.Type, r.Action.ID)
		// The last rule without conditions is Proxifier's "Default".
		if i == len(x.Rules)-1 && len(apps) == 0 && len(hosts) == 0 && ports == "" {
			if ok {
				p.Default = a
			}
			continue
		}
		if !ok {
			continue
		}
		p.Rules = append(p.Rules, config.Rule{
			ID: config.NewID(), Name: name, Enabled: on(r.Enabled),
			Apps: apps, Hosts: hosts, Ports: ports, Action: a,
		})
	}

	p.Normalize()
	if err := p.Validate(); err != nil {
		return nil, notes, err
	}
	return p, notes, nil
}

// split breaks Proxifier's "a; b; "c d"" lists.
func split(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }) {
		if f = strings.Trim(strings.TrimSpace(f), `"`); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// targets rewrites the patterns Proxifier allows and rules here do not.
func targets(in []string) []string {
	var out []string
	for _, t := range in {
		switch {
		case strings.EqualFold(t, "%ComputerName%"):
			t = "localhost"
		case strings.Contains(t, "%"):
			continue
		}
		if pfx, ok := wildcardNet(t); ok {
			t = pfx
		}
		out = append(out, t)
	}
	return out
}

// wildcardNet turns "192.168.*.*" into "192.168.0.0/16".
func wildcardNet(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 || !strings.Contains(s, "*") {
		return "", false
	}
	bits := 32
	for i := 3; i >= 0 && parts[i] == "*"; i-- {
		parts[i] = "0"
		bits -= 8
	}
	a, err := netip.ParseAddr(strings.Join(parts, "."))
	if err != nil || bits == 32 {
		return "", false
	}
	return netip.PrefixFrom(a, bits).String(), true
}

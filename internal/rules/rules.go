// Package rules implements Proxifier-style rule matching: each rule may
// constrain the application, the target host and the target port; the first
// enabled rule whose constraints all match decides the action.
package rules

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"oddlyproxifier/internal/config"
)

// Request describes one connection to be classified.
type Request struct {
	App  string     // full executable path, may be empty
	Host string     // hostname, may be empty
	IP   netip.Addr // may be invalid when only the hostname is known
	Port int
}

type hostPattern struct {
	glob   string // lower-case wildcard, matched against hostname and IP text
	prefix netip.Prefix
	lo, hi netip.Addr
}

type portRange struct{ lo, hi int }

type rule struct {
	name   string
	apps   []string // lower-case globs
	hosts  []hostPattern
	ports  []portRange
	action config.Action
}

type Set struct {
	rules     []rule
	def       config.Action
	hostNames bool
}

// HostNames reports whether some enabled rule matches on host names, i.e.
// whether learning a connection's hostname can change the decision.
func (s *Set) HostNames() bool { return s.hostNames }

const DefaultRuleName = "Default"

// Compile validates and pre-parses all enabled rules.
func Compile(p *config.Profile) (*Set, error) {
	s := &Set{def: p.Default}
	for _, r := range p.Rules {
		cr := rule{name: r.Name, action: r.Action}
		for _, a := range splitList(r.Apps) {
			cr.apps = append(cr.apps, normPath(a))
		}
		for _, h := range splitList(r.Hosts) {
			hp, err := parseHost(h)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", r.Name, err)
			}
			cr.hosts = append(cr.hosts, hp)
		}
		pr, err := ParsePorts(r.Ports)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		cr.ports = pr
		if r.Enabled {
			s.rules = append(s.rules, cr)
			for _, h := range cr.hosts {
				if h.glob != "" {
					s.hostNames = true
				}
			}
		}
	}
	return s, nil
}

// Nets returns the address-based entries of a rule's host list as prefixes.
// Name patterns are skipped, and so are ranges that would need an
// unreasonable number of prefixes.
func Nets(hosts []string) []netip.Prefix {
	var out []netip.Prefix
	for _, h := range splitList(hosts) {
		hp, err := parseHost(h)
		if err != nil || hp.glob != "" {
			continue
		}
		if hp.prefix.IsValid() {
			out = append(out, hp.prefix)
			continue
		}
		out = append(out, rangePrefixes(hp.lo, hp.hi)...)
	}
	return out
}

// AppNames returns, for each application pattern, a glob on the executable
// name alone that matches at least everything the pattern matches. Patterns
// that cannot be narrowed down to a name yield "*".
func AppNames(apps []string) []string {
	var out []string
	for _, a := range splitList(apps) {
		a = normPath(a)
		if i := strings.LastIndexByte(a, '/'); i >= 0 {
			// In a path pattern the wildcards also match separators, so a
			// wildcard in the last segment may swallow directory names.
			if a = a[i+1:]; a == "" || strings.ContainsAny(a, "*?") {
				a = "*"
			}
		}
		out = append(out, a)
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// rangePrefixes covers lo..hi with the smallest list of prefixes.
func rangePrefixes(lo, hi netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for {
		bits := lo.BitLen()
		for bits > 0 {
			p, err := lo.Prefix(bits - 1)
			if err != nil || p.Addr() != lo || lastAddr(p).Compare(hi) > 0 {
				break
			}
			bits--
		}
		p, _ := lo.Prefix(bits)
		out = append(out, p)
		last := lastAddr(p)
		if last.Compare(hi) >= 0 {
			return out
		}
		if len(out) >= 64 {
			return nil
		}
		lo = last.Next()
	}
}

// Match returns the name of the deciding rule and its action.
func (s *Set) Match(q Request) (string, config.Action) {
	app := normPath(q.App)
	base := app
	if i := strings.LastIndexByte(app, '/'); i >= 0 {
		base = app[i+1:]
	}
	host := strings.ToLower(strings.TrimSuffix(q.Host, "."))
	// A zone ("fe80::1%eth0") says which interface, not which network.
	ip := q.IP.Unmap().WithZone("")
	if !ip.IsValid() && host != "" {
		if a, err := netip.ParseAddr(host); err == nil {
			ip, host = a.Unmap().WithZone(""), ""
		}
	}
	for i := range s.rules {
		r := &s.rules[i]
		if len(r.apps) > 0 && !matchApp(r.apps, app, base) {
			continue
		}
		if len(r.hosts) > 0 && !matchHost(r.hosts, host, ip) {
			continue
		}
		if len(r.ports) > 0 && !matchPort(r.ports, q.Port) {
			continue
		}
		return r.name, r.action
	}
	return DefaultRuleName, s.def
}

func matchApp(pats []string, full, base string) bool {
	if full == "" {
		return false
	}
	for _, p := range pats {
		if strings.ContainsRune(p, '/') {
			if Glob(p, full) {
				return true
			}
		} else if Glob(p, base) {
			return true
		}
	}
	return false
}

func matchHost(pats []hostPattern, host string, ip netip.Addr) bool {
	for i := range pats {
		p := &pats[i]
		switch {
		case p.glob != "":
			if host != "" && Glob(p.glob, host) {
				return true
			}
			if ip.IsValid() && Glob(p.glob, ip.String()) {
				return true
			}
		case p.prefix.IsValid():
			if ip.IsValid() && p.prefix.Contains(ip) {
				return true
			}
		default:
			if ip.IsValid() && ip.BitLen() == p.lo.BitLen() && ip.Compare(p.lo) >= 0 && ip.Compare(p.hi) <= 0 {
				return true
			}
		}
	}
	return false
}

func matchPort(rs []portRange, port int) bool {
	for _, r := range rs {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

func parseHost(s string) (hostPattern, error) {
	s = strings.ToLower(s)
	if strings.ContainsRune(s, '/') {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return hostPattern{}, fmt.Errorf("bad network %q", s)
		}
		return hostPattern{prefix: pfx.Masked()}, nil
	}
	if a, b, ok := strings.Cut(s, "-"); ok {
		lo, e1 := netip.ParseAddr(strings.TrimSpace(a))
		hi, e2 := netip.ParseAddr(strings.TrimSpace(b))
		if e1 == nil && e2 == nil {
			lo, hi = lo.Unmap(), hi.Unmap()
			if lo.BitLen() != hi.BitLen() || lo.Compare(hi) > 0 {
				return hostPattern{}, fmt.Errorf("bad address range %q", s)
			}
			return hostPattern{lo: lo, hi: hi}, nil
		}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return hostPattern{lo: a, hi: a}, nil
	}
	if strings.ContainsAny(s, " \t") {
		return hostPattern{}, fmt.Errorf("bad host pattern %q", s)
	}
	return hostPattern{glob: strings.TrimSuffix(s, ".")}, nil
}

// ParsePorts parses "80, 443; 8000-9000". Empty means any port.
func ParsePorts(s string) ([]portRange, error) {
	var out []portRange
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		a, b, isRange := strings.Cut(f, "-")
		lo, err := strconv.Atoi(a)
		hi := lo
		if err == nil && isRange {
			hi, err = strconv.Atoi(b)
		}
		if err != nil || lo < 0 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("bad port spec %q", f)
		}
		out = append(out, portRange{lo, hi})
	}
	return out, nil
}

// splitList accepts both a JSON list and Proxifier's "a; b; c" single string.
func splitList(in []string) []string {
	var out []string
	for _, item := range in {
		for _, f := range strings.FieldsFunc(item, func(r rune) bool { return r == ';' || r == ',' || r == '\n' }) {
			if f = strings.Trim(strings.TrimSpace(f), `"`); f != "" {
				out = append(out, f)
			}
		}
	}
	return out
}

func normPath(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, `\`, "/"))
}

// Glob matches s against a pattern with '*' (any run) and '?' (any one byte).
func Glob(pattern, s string) bool {
	px, sx, star, mark := 0, 0, -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]):
			px++
			sx++
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// HostList is a compiled list of host patterns, for uses outside of rules.
type HostList struct{ pats []hostPattern }

// CompileHosts parses host patterns as rules do: names with wildcards,
// networks and address ranges.
func CompileHosts(hosts []string) (*HostList, error) {
	l := &HostList{}
	for _, h := range splitList(hosts) {
		hp, err := parseHost(h)
		if err != nil {
			return nil, err
		}
		l.pats = append(l.pats, hp)
	}
	return l, nil
}

// Match reports whether host or ip is on the list. An empty list matches nothing.
func (l *HostList) Match(host string, ip netip.Addr) bool {
	return l != nil && len(l.pats) > 0 && matchHost(l.pats, strings.ToLower(strings.TrimSuffix(host, ".")), ip)
}

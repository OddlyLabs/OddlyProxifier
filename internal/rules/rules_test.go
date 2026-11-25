package rules

import (
	"net/netip"
	"reflect"
	"testing"

	"oddlyproxifier/internal/config"
)

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"", "", true},
		{"", "a", false},
		{"*", "", true},
		{"*", "anything", true},
		{"chrome.exe", "chrome.exe", true},
		{"chrome.exe", "chrome.exe2", false},
		{"chrome*", "chrome.exe", true},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "badexample.com", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a*b*c", "a--b--c", true},
		{"a*b*c", "a--b--", false},
		{"*a*", "bab", true},
		{"**x", "x", true},
		{"10.0.*", "10.0.12.7", true},
		{"10.0.*", "10.1.12.7", false},
	}
	for _, c := range cases {
		if got := Glob(c.pattern, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	good := map[string][]portRange{
		"":                nil,
		"80":              {{80, 80}},
		"80,443":          {{80, 80}, {443, 443}},
		"80; 443":         {{80, 80}, {443, 443}},
		"8000-9000":       {{8000, 9000}},
		" 22 , 1000-2000": {{22, 22}, {1000, 2000}},
		"0-65535":         {{0, 65535}},
	}
	for in, want := range good {
		got, err := ParsePorts(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ParsePorts(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"x", "80-", "-80", "90-80", "70000", "1-70000", "80,,x"} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) succeeded, want an error", in)
		}
	}
}

// profile enables every rule except those with the ID "off".
func profile(rules ...config.Rule) *config.Profile {
	p := &config.Profile{Rules: rules, Default: config.Action{Type: config.ActionDirect}}
	for i := range p.Rules {
		p.Rules[i].Enabled = p.Rules[i].ID != "off"
	}
	p.Normalize()
	return p
}

var (
	direct = config.Action{Type: config.ActionDirect}
	block  = config.Action{Type: config.ActionBlock}
	viaP1  = config.Action{Type: config.ActionProxy, Target: "p1"}
	viaC1  = config.Action{Type: config.ActionChain, Target: "c1"}
)

func mustCompile(t *testing.T, p *config.Profile) *Set {
	t.Helper()
	s, err := Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return s
}

func TestMatch(t *testing.T) {
	set := mustCompile(t, profile(
		config.Rule{Name: "local", Hosts: []string{"localhost", "127.0.0.0/8", "::1", "192.168.0.0/16", "fe80::/10"}, Action: direct},
		config.Rule{ID: "off", Name: "off", Apps: []string{"firefox.exe"}, Action: block},
		config.Rule{Name: "browsers", Apps: []string{"chrome.exe; firefox.exe", `*\Opera\*`}, Action: viaP1},
		config.Rule{Name: "web", Hosts: []string{"*.example.com", "example.com"}, Ports: "80,443", Action: viaC1},
		config.Rule{Name: "range", Hosts: []string{"10.1.1.10-10.1.1.20"}, Action: block},
		config.Rule{Name: "single", Hosts: []string{"203.0.113.9"}, Ports: "1000-2000", Action: block},
		config.Rule{Name: "ipglob", Hosts: []string{"198.51.*"}, Action: viaP1},
		config.Rule{Name: "v6", Hosts: []string{"2001:db8::/32"}, Action: viaP1},
	))

	ip := netip.MustParseAddr
	cases := []struct {
		name string
		q    Request
		rule string
		act  config.Action
	}{
		{"name of the local machine", Request{Host: "localhost", Port: 80}, "local", direct},
		{"loopback address", Request{IP: ip("127.0.0.1"), Port: 80}, "local", direct},
		{"IPv6 loopback", Request{IP: ip("::1"), Port: 80}, "local", direct},
		{"private network", Request{IP: ip("192.168.7.7"), Port: 445}, "local", direct},
		{"IPv4-mapped address is unmapped", Request{IP: ip("::ffff:192.168.7.7"), Port: 445}, "local", direct},
		{"link-local with a zone", Request{IP: ip("fe80::1%eth0"), Port: 80}, "local", direct},
		{"address literal given as host", Request{Host: "192.168.1.1", Port: 80}, "local", direct},

		{"application by name", Request{App: `C:\Program Files\Google\Chrome\chrome.exe`, IP: ip("8.8.8.8"), Port: 443}, "browsers", viaP1},
		{"application name is case-insensitive", Request{App: `C:\X\CHROME.EXE`, IP: ip("8.8.8.8"), Port: 443}, "browsers", viaP1},
		{"second name of a ';' list", Request{App: "/usr/bin/firefox.exe", IP: ip("8.8.8.8"), Port: 443}, "browsers", viaP1},
		{"application by path pattern", Request{App: `C:\Users\me\AppData\Opera\launcher.exe`, IP: ip("8.8.8.8"), Port: 443}, "browsers", viaP1},
		{"local rule wins over the application", Request{App: "chrome.exe", IP: ip("127.0.0.1"), Port: 443}, "local", direct},
		{"unknown application never matches an app rule", Request{IP: ip("8.8.8.8"), Port: 443}, DefaultRuleName, direct},
		{"other application", Request{App: "notepad.exe", IP: ip("8.8.8.8"), Port: 443}, DefaultRuleName, direct},

		{"host wildcard", Request{Host: "www.example.com", Port: 443}, "web", viaC1},
		{"host wildcard, upper case and trailing dot", Request{Host: "WWW.Example.COM.", Port: 80}, "web", viaC1},
		{"bare domain", Request{Host: "example.com", Port: 443}, "web", viaC1},
		{"host matches, port does not", Request{Host: "www.example.com", Port: 8080}, DefaultRuleName, direct},
		{"look-alike domain", Request{Host: "notexample.com", Port: 443}, DefaultRuleName, direct},
		{"name rule needs the name", Request{IP: ip("93.184.216.34"), Port: 443}, DefaultRuleName, direct},

		{"start of a range", Request{IP: ip("10.1.1.10"), Port: 1}, "range", block},
		{"end of a range", Request{IP: ip("10.1.1.20"), Port: 1}, "range", block},
		{"below a range", Request{IP: ip("10.1.1.9"), Port: 1}, DefaultRuleName, direct},
		{"above a range", Request{IP: ip("10.1.1.21"), Port: 1}, DefaultRuleName, direct},

		{"single address and port range", Request{IP: ip("203.0.113.9"), Port: 1500}, "single", block},
		{"single address, port outside", Request{IP: ip("203.0.113.9"), Port: 2001}, DefaultRuleName, direct},

		{"wildcard on the address text", Request{IP: ip("198.51.100.20"), Port: 80}, "ipglob", viaP1},
		{"IPv6 network", Request{IP: ip("2001:db8:1::5"), Port: 80}, "v6", viaP1},
		{"IPv6 outside the network", Request{IP: ip("2001:db9::5"), Port: 80}, DefaultRuleName, direct},
	}
	for _, c := range cases {
		rule, act := set.Match(c.q)
		if rule != c.rule || act != c.act {
			t.Errorf("%s: got rule %q %+v, want %q %+v", c.name, rule, act, c.rule, c.act)
		}
	}
	if !set.HostNames() {
		t.Error("HostNames() = false although rules match on names")
	}
}

func TestMatchKnowsBothNameAndAddress(t *testing.T) {
	set := mustCompile(t, profile(
		config.Rule{Name: "by net", Hosts: []string{"203.0.113.0/24"}, Action: block},
		config.Rule{Name: "by name", Hosts: []string{"*.example.net"}, Action: viaP1},
	))
	q := Request{Host: "api.example.net", IP: netip.MustParseAddr("203.0.113.4"), Port: 443}
	if rule, _ := set.Match(q); rule != "by net" {
		t.Errorf("first matching rule should win, got %q", rule)
	}
	q.IP = netip.MustParseAddr("198.51.100.1")
	if rule, _ := set.Match(q); rule != "by name" {
		t.Errorf("got %q, want the name rule", rule)
	}
}

func TestDefaultActionAndHostNames(t *testing.T) {
	p := profile(config.Rule{Name: "lan", Hosts: []string{"10.0.0.0/8"}, Action: direct})
	p.Default = viaP1
	set := mustCompile(t, p)
	if rule, act := set.Match(Request{IP: netip.MustParseAddr("1.1.1.1"), Port: 53}); rule != DefaultRuleName || act != viaP1 {
		t.Errorf("got %q %+v, want the default action", rule, act)
	}
	if set.HostNames() {
		t.Error("HostNames() = true although no rule matches on names")
	}

	// A disabled rule must not switch name sniffing on.
	p = profile(config.Rule{ID: "off", Name: "off", Hosts: []string{"*.example.com"}, Action: block})
	if mustCompile(t, p).HostNames() {
		t.Error("a disabled rule counts for HostNames()")
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []config.Rule{
		{Name: "net", Hosts: []string{"10.0.0.0/40"}},
		{Name: "range", Hosts: []string{"10.0.0.9-10.0.0.1"}},
		{Name: "mixed range", Hosts: []string{"10.0.0.1-::1"}},
		{Name: "space", Hosts: []string{"two words"}},
		{Name: "port", Ports: "http"},
	}
	for _, r := range bad {
		if _, err := Compile(profile(r)); err == nil {
			t.Errorf("rule %q compiled, want an error", r.Name)
		}
	}
	// Disabled rules are checked as well: they can be switched on any time.
	r := bad[0]
	r.ID = "off"
	if _, err := Compile(profile(r)); err == nil {
		t.Error("a disabled rule with a bad pattern compiled")
	}
}

func TestNets(t *testing.T) {
	got := Nets([]string{"localhost", "10.0.0.0/8; 192.168.1.7", "*.example.com", "10.1.1.0-10.1.1.255", "172.16.0.5-172.16.0.6", "::1"})
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.7/32"),
		netip.MustParsePrefix("10.1.1.0/24"),
		netip.MustParsePrefix("172.16.0.5/32"),
		netip.MustParsePrefix("172.16.0.6/32"),
		netip.MustParsePrefix("::1/128"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Nets = %v\nwant   %v", got, want)
	}
}

func TestRangePrefixesCoverExactly(t *testing.T) {
	lo, hi := netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("10.0.1.17")
	pfx := rangePrefixes(lo, hi)
	if len(pfx) == 0 {
		t.Fatal("no prefixes")
	}
	inside := func(a netip.Addr) bool {
		for _, p := range pfx {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for a := netip.MustParseAddr("10.0.0.0"); a.Compare(netip.MustParseAddr("10.0.2.0")) < 0; a = a.Next() {
		want := a.Compare(lo) >= 0 && a.Compare(hi) <= 0
		if inside(a) != want {
			t.Fatalf("%v: covered = %v, want %v (prefixes %v)", a, inside(a), want, pfx)
		}
	}
	// A range that would need too many prefixes is given up on.
	if got := rangePrefixes(netip.MustParseAddr("::1"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")); got != nil {
		t.Errorf("huge range gave %d prefixes, want none", len(got))
	}
}

func TestAppNames(t *testing.T) {
	got := AppNames([]string{"Chrome.exe", `C:\Tools\curl.exe`, `*\Steam\*`, "/opt/app/bin/", "fire*.exe", `D:\Games\*\game?.exe`})
	want := []string{"chrome.exe", "curl.exe", "*", "*", "fire*.exe", "*"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AppNames = %q, want %q", got, want)
	}
}

// Every application a rule matches must also be matched by the name globs
// handed to the kernel pre-filter, or its connections would never arrive.
func TestAppNamesNeverNarrower(t *testing.T) {
	patterns := []string{"chrome.exe", `c:\tools\curl.exe`, `*\steam\*`, "fire*.exe", `d:\games\*\game?.exe`, "*/bin/tool"}
	paths := []string{
		`c:\program files\google\chrome.exe`, `c:\tools\curl.exe`, `d:\x\steam\bin\hl.exe`, `c:\steam\steam.exe`,
		`c:\ff\firefox.exe`, `d:\games\a\b\game1.exe`, `/usr/bin/tool`, `/opt/x/bin/tool`, `c:\other\thing.exe`,
	}
	for _, pat := range patterns {
		names := AppNames([]string{pat})
		for _, path := range paths {
			full := normPath(path)
			base := full
			for i := len(full) - 1; i >= 0; i-- {
				if full[i] == '/' {
					base = full[i+1:]
					break
				}
			}
			if matchApp([]string{normPath(pat)}, full, base) && !Glob(names[0], base) {
				t.Errorf("pattern %q matches %q, but its name glob %q does not match %q", pat, path, names[0], base)
			}
		}
	}
}

func TestHostList(t *testing.T) {
	var none *HostList
	if none.Match("example.com", netip.Addr{}) {
		t.Error("a nil list matched")
	}
	l, err := CompileHosts([]string{"localhost", "*.Corp.Example", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"localhost": true, "LOCALHOST": true, "git.corp.example": true, "corp.example": false, "example.com": false, "": false,
	} {
		if got := l.Match(host, netip.Addr{}); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
	if !l.Match("", netip.MustParseAddr("10.1.2.3")) || l.Match("", netip.MustParseAddr("11.1.2.3")) {
		t.Error("the network pattern does not match by address")
	}
	if empty, err := CompileHosts(nil); err != nil || empty.Match("localhost", netip.Addr{}) {
		t.Errorf("empty list: %v", err)
	}
	if _, err := CompileHosts([]string{"10.0.0.0/99"}); err == nil {
		t.Error("a bad pattern was accepted")
	}
}

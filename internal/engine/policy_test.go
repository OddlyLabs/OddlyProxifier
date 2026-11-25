package engine

import (
	"net/netip"
	"strings"
	"testing"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/dnsx"
	"oddlyproxifier/internal/intercept"
)

func prefixList(nets []netip.Prefix) string {
	s := make([]string, len(nets))
	for i, n := range nets {
		s[i] = n.String()
	}
	return strings.Join(s, " ")
}

// What the default profile's "Localhost / LAN" rule turns into. The name
// "localhost" has no address and is left to the engine.
const lanNets = "127.0.0.0/8 ::1/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 fe80::/10 fc00::/7"

func TestBuildPolicy(t *testing.T) {
	px := config.Proxy{ID: "px", Name: "px", Type: config.TypeSOCKS5, Host: "192.0.2.1", Port: 1080}
	direct := config.Action{Type: config.ActionDirect}
	viaPx := config.Action{Type: config.ActionProxy, Target: "px"}
	block := config.Action{Type: config.ActionBlock}
	rule := func(name string, a config.Action, apps, hosts []string, ports string) config.Rule {
		return config.Rule{ID: name, Name: name, Enabled: true, Apps: apps, Hosts: hosts, Ports: ports, Action: a}
	}

	cases := []struct {
		name    string
		edit    func(p *config.Profile)
		needed  bool
		mode    intercept.Mode
		apps    string
		exclude string
		bypass  string
	}{
		{
			name:   "default profile: nothing to intercept",
			edit:   func(p *config.Profile) {},
			needed: false,
		},
		{
			name: "proxy rule for every application",
			edit: func(p *config.Profile) {
				p.Rules = append(p.Rules, rule("all", viaPx, nil, nil, ""))
			},
			needed: true, mode: intercept.ModeAll, bypass: lanNets,
		},
		{
			name: "proxy rule for two applications",
			edit: func(p *config.Profile) {
				p.Rules = append(p.Rules, rule("two", viaPx, []string{"Firefox.exe", "curl.exe"}, nil, ""))
			},
			needed: true, mode: intercept.ModeApps, apps: "curl.exe firefox.exe", bypass: lanNets,
		},
		{
			name: "application given by path",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{rule("path", viaPx, []string{`C:\Tools\Curl.exe`}, nil, "")}
			},
			needed: true, mode: intercept.ModeApps, apps: "curl.exe",
		},
		{
			name: "path pattern that cannot be narrowed to a name",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{rule("steam", viaPx, []string{`*\Steam\*`}, nil, "")}
			},
			needed: true, mode: intercept.ModeAll,
		},
		{
			name: "one rule for some applications, one for all",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{
					rule("some", viaPx, []string{"curl.exe"}, nil, ""),
					rule("blocked port", block, nil, nil, "25"),
				}
			},
			needed: true, mode: intercept.ModeAll,
		},
		{
			name: "default action is a proxy",
			edit: func(p *config.Profile) {
				p.Rules = append(p.Rules, rule("some", block, []string{"curl.exe"}, nil, ""))
				p.Default = viaPx
			},
			needed: true, mode: intercept.ModeAll, bypass: lanNets,
		},
		{
			name: "block rule alone",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{rule("ads", block, nil, []string{"*.ads.test"}, "")}
			},
			needed: true, mode: intercept.ModeAll,
		},
		{
			name: "disabled proxy rule",
			edit: func(p *config.Profile) {
				r := rule("off", viaPx, nil, nil, "")
				r.Enabled = false
				p.Rules = append(p.Rules, r)
			},
			needed: false,
		},
		{
			name: "direct rule after a proxy rule is not skipped",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{
					rule("web", viaPx, nil, nil, "80,443"),
					rule("lan", direct, nil, []string{"10.0.0.0/8"}, ""),
				}
			},
			needed: true, mode: intercept.ModeAll,
		},
		{
			name: "leading direct rule for applications",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{
					rule("games", direct, []string{"Steam.exe", "game?.exe"}, nil, ""),
					rule("all", viaPx, nil, nil, ""),
				}
			},
			needed: true, mode: intercept.ModeAll, exclude: "steam.exe game?.exe",
		},
		{
			name: "leading direct rule with a path pattern",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{
					rule("games", direct, []string{`C:\Games\*`}, nil, ""),
					rule("all", viaPx, nil, nil, ""),
				}
			},
			needed: true, mode: intercept.ModeAll,
		},
		{
			name: "leading direct rule with hosts and ports",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{
					rule("lan web", direct, nil, []string{"10.0.0.0/8"}, "80"),
					rule("all", viaPx, nil, nil, ""),
				}
			},
			needed: true, mode: intercept.ModeAll,
		},
		{
			name: "leading direct rule with hosts and applications",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{
					rule("lan curl", direct, []string{"curl.exe"}, []string{"10.0.0.0/8"}, ""),
					rule("all", viaPx, nil, nil, ""),
				}
			},
			needed: true, mode: intercept.ModeAll,
		},
		{
			name: "address range and single address",
			edit: func(p *config.Profile) {
				p.Rules = []config.Rule{
					rule("few", direct, nil, []string{"192.0.2.4-192.0.2.7", "192.0.2.99", "*.corp.test"}, ""),
					rule("all", viaPx, nil, nil, ""),
				}
			},
			needed: true, mode: intercept.ModeAll, bypass: "192.0.2.4/30 192.0.2.99/32",
		},
		{
			name: "everything is to be shown",
			edit: func(p *config.Profile) {
				p.Options.HandleDirect = true
			},
			needed: true, mode: intercept.ModeAll,
		},
		{
			name: "everything is to be shown, with application rules",
			edit: func(p *config.Profile) {
				p.Options.HandleDirect = true
				p.Rules = append(p.Rules, rule("one", viaPx, []string{"curl.exe"}, nil, ""))
			},
			needed: true, mode: intercept.ModeAll,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Proxies = []config.Proxy{px}
			tc.edit(p)
			if err := p.Validate(); err != nil {
				t.Fatalf("the test's profile is invalid: %v", err)
			}
			pol, needed := buildPolicy(p, nil)
			if needed != tc.needed {
				t.Fatalf("needed = %v, want %v", needed, tc.needed)
			}
			if !needed {
				return
			}
			if pol.Mode != tc.mode {
				t.Errorf("mode = %v, want %v", pol.Mode, tc.mode)
			}
			if got := strings.Join(pol.Apps, " "); got != tc.apps {
				t.Errorf("applications = %q, want %q", got, tc.apps)
			}
			if got := strings.Join(pol.ExcludeApps, " "); got != tc.exclude {
				t.Errorf("excluded applications = %q, want %q", got, tc.exclude)
			}
			if got := prefixList(pol.BypassNets); got != tc.bypass {
				t.Errorf("bypassed networks = %q, want %q", got, tc.bypass)
			}
			if len(pol.ForceNets) != 0 || pol.DNSPort != 0 {
				t.Errorf("fake DNS settings without fake DNS: %v, port %d", pol.ForceNets, pol.DNSPort)
			}
		})
	}
}

func TestBuildPolicyOptions(t *testing.T) {
	p := config.Default()
	p.Default = config.Action{Type: config.ActionBlock}
	p.Options.TransparentPort = 40123
	p.Options.IPv6 = false
	p.Options.TargetPort = 8443
	p.Options.BlockQUIC = false
	pol, needed := buildPolicy(p, nil)
	if !needed || pol.Port != 40123 || pol.IPv6 || pol.TargetPort != 8443 || pol.BlockQUIC {
		t.Errorf("needed %v, policy %+v", needed, pol)
	}

	p = config.Default()
	p.Default = config.Action{Type: config.ActionBlock}
	pol, _ = buildPolicy(p, nil)
	if pol.Port != 37080 || !pol.IPv6 || pol.TargetPort != 0 || !pol.BlockQUIC {
		t.Errorf("policy of the default options: %+v", pol)
	}
}

func TestBuildPolicyFakeDNS(t *testing.T) {
	f, err := dnsx.NewFake("198.18.0.0/15", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}

	// Not listening yet: the range is forced through the engine all the same.
	pol, needed := buildPolicy(config.Default(), f)
	if !needed || prefixList(pol.ForceNets) != "198.18.0.0/15" || pol.DNSPort != 0 {
		t.Errorf("before listening: needed %v, force %v, DNS port %d", needed, pol.ForceNets, pol.DNSPort)
	}

	if err := f.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	port := int(netip.MustParseAddrPort(f.Addr().String()).Port())
	pol, needed = buildPolicy(config.Default(), f)
	if !needed || prefixList(pol.ForceNets) != "198.18.0.0/15" || pol.DNSPort != port {
		t.Errorf("needed %v, force %v, DNS port %d (want %d)", needed, pol.ForceNets, pol.DNSPort, port)
	}
	// The default profile's direct rule comes first, so the LAN stays out.
	if got := prefixList(pol.BypassNets); got != lanNets {
		t.Errorf("bypassed networks = %q, want %q", got, lanNets)
	}
	if pol.Mode != intercept.ModeAll {
		t.Errorf("mode = %v, want all applications", pol.Mode)
	}
}

package engine

import (
	"net/netip"
	"sort"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/dnsx"
	"oddlyproxifier/internal/intercept"
	"oddlyproxifier/internal/rules"
)

// buildPolicy derives the coarse pre-filter for the interception backend
// from the profile. The backend may only skip what the rules would send
// direct anyway; everything else is still classified by the engine.
//
// needed is false when no connection can ever be proxied or blocked, in
// which case nothing has to be intercepted at all.
func buildPolicy(prof *config.Profile, fake *dnsx.Fake) (pol intercept.Policy, needed bool) {
	o := prof.Options
	pol = intercept.Policy{
		Port:       o.TransparentPort,
		IPv6:       o.IPv6,
		TargetPort: o.TargetPort,
		BlockQUIC:  o.BlockQUIC,
	}

	appsOnly := prof.Default.Type == config.ActionDirect
	apps := map[string]bool{}
	head := true // still inside the leading run of "direct" rules
	for _, r := range prof.Rules {
		if !r.Enabled {
			continue
		}
		if r.Action.Type != config.ActionDirect {
			head = false
			needed = true
			names := rules.AppNames(r.Apps)
			if len(names) == 0 {
				appsOnly = false
			}
			for _, n := range names {
				if n == "*" {
					appsOnly = false
				}
				apps[n] = true
			}
			continue
		}
		if !head || o.HandleDirect {
			continue
		}
		// A direct rule that nothing can override: it is matched before any
		// proxy or block rule, so what it covers never needs the engine.
		noApps, noHosts, noPorts := len(rules.AppNames(r.Apps)) == 0, len(r.Hosts) == 0, r.Ports == ""
		switch {
		case noApps && noPorts && !noHosts:
			pol.BypassNets = append(pol.BypassNets, rules.Nets(r.Hosts)...)
		case !noApps && noHosts && noPorts && namesOnly(r.Apps):
			pol.ExcludeApps = append(pol.ExcludeApps, rules.AppNames(r.Apps)...)
		}
	}
	if prof.Default.Type != config.ActionDirect {
		needed = true
	}
	if o.HandleDirect {
		// Everything is to be shown and logged, so nothing may be skipped.
		needed, appsOnly = true, false
	}

	if fake != nil {
		// Placeholder addresses only mean something to the engine.
		pol.ForceNets = append(pol.ForceNets, fake.Range())
		needed = true
		if a, ok := addrPort2(fake); ok {
			pol.DNSPort = int(a.Port())
		}
	}
	if !needed {
		return pol, false
	}

	if appsOnly && len(apps) > 0 {
		pol.Mode = intercept.ModeApps
		for a := range apps {
			pol.Apps = append(pol.Apps, a)
		}
		sort.Strings(pol.Apps)
	}

	return pol, true
}

// namesOnly reports whether every pattern is a plain executable name, which
// is all the kernel pre-filter can match.
func namesOnly(apps []string) bool {
	for _, a := range apps {
		for _, c := range a {
			if c == '/' || c == '\\' {
				return false
			}
		}
	}
	return true
}

// addrPort2 returns the UDP address the fake DNS server listens on.
func addrPort2(f *dnsx.Fake) (netip.AddrPort, bool) {
	a := f.Addr()
	if a == nil {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

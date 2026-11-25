//go:build linux

package intercept

import (
	"strings"
	"testing"
)

func lines(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }

// index returns the position of the first line containing sub, or -1.
func index(ls []string, sub string) int {
	for i, l := range ls {
		if strings.Contains(l, sub) {
			return i
		}
	}
	return -1
}

func TestNftScript(t *testing.T) {
	p := Policy{
		Port: 39999, IPv6: true, DNSPort: 39953, BlockQUIC: true,
		ForceNets:  prefixes("198.18.0.0/15"),
		BypassNets: prefixes("10.0.0.0/8", "10.9.0.0/16", "fd00::/8"),
	}
	s := nftScript(p)
	ls := lines(s)

	// Each family is replaced as a whole, in one transaction.
	for _, fam := range []string{"ip", "ip6"} {
		decl := index(ls, "table "+fam+" oddlyproxifier")
		del := index(ls, "delete table "+fam+" oddlyproxifier")
		def := index(ls, "table "+fam+" oddlyproxifier {")
		if decl < 0 || del != decl+1 || def != del+1 {
			t.Errorf("%s: declare/delete/define at lines %d/%d/%d", fam, decl, del, def)
		}
	}

	// Order inside the chain decides who wins.
	mark := index(ls, "meta mark 0x4f44 return")
	force := index(ls, "ip daddr { 198.18.0.0/15 } meta l4proto tcp redirect to :39999")
	dns := index(ls, "ip daddr != 127.0.0.0/8 udp dport 53 redirect to :39953")
	bypass := index(ls, "ip daddr { ")
	for i, l := range ls { // the first bypass line after the DNS rule
		if i > dns && strings.Contains(l, "ip daddr {") && strings.HasSuffix(l, "return") {
			bypass = i
			break
		}
	}
	all := index(ls, "\t\tmeta l4proto tcp redirect to :39999")
	if !(mark >= 0 && mark < force && force < dns && dns < bypass && bypass < all) {
		t.Errorf("rule order: mark %d, force %d, dns %d, bypass %d, redirect %d\n%s", mark, force, dns, bypass, all, s)
	}
	if b := ls[bypass]; !strings.Contains(b, "127.0.0.0/8") || !strings.Contains(b, "10.0.0.0/8") || strings.Contains(b, "10.9.0.0/16") {
		t.Errorf("IPv4 bypass set: %s", b)
	}
	if !strings.Contains(s, "ip6 daddr { fd00::/8, ff00::/8, ::/128, ::1/128 } return") {
		t.Errorf("IPv6 bypass set:\n%s", s)
	}
	if strings.Count(s, "udp dport 443 reject") != 2 {
		t.Errorf("QUIC is not rejected in both families:\n%s", s)
	}
	if strings.Count(s, "type nat hook output priority -100") != 2 || strings.Count(s, "type filter hook output priority 0") != 2 {
		t.Errorf("hooks:\n%s", s)
	}
	if strings.Count(s, "{") != strings.Count(s, "}") {
		t.Errorf("unbalanced braces:\n%s", s)
	}
}

func TestNftScriptMinimal(t *testing.T) {
	s := nftScript(Policy{Port: 39999})
	if strings.Contains(s, "table ip6 oddlyproxifier {") {
		t.Error("IPv6 is intercepted although it is switched off")
	}
	// A table left behind by a run with IPv6 has to go.
	if !strings.Contains(s, "table ip6 oddlyproxifier\ndelete table ip6 oddlyproxifier\n") {
		t.Error("the IPv6 table of an earlier run is not removed")
	}
	for _, unwanted := range []string{"udp dport 53", "udp dport 443", "filter_out", "198.18."} {
		if strings.Contains(s, unwanted) {
			t.Errorf("%q in a policy that did not ask for it:\n%s", unwanted, s)
		}
	}
	if !strings.Contains(s, "ip daddr { 224.0.0.0/4, 0.0.0.0/8, 127.0.0.0/8, 255.255.255.255/32 } return") {
		t.Errorf("the built-in bypass list is missing:\n%s", s)
	}

	s = nftScript(Policy{Port: 39999, TargetPort: 8443})
	if !strings.Contains(s, "tcp dport 8443 redirect to :39999") || strings.Contains(s, "meta l4proto tcp redirect") {
		t.Errorf("single-port mode:\n%s", s)
	}
}

func TestIptRules(t *testing.T) {
	p := Policy{
		Port: 39999, IPv6: true, DNSPort: 39953, BlockQUIC: true,
		ForceNets:  prefixes("198.18.0.0/15"),
		BypassNets: prefixes("10.0.0.0/8", "fd00::/8"),
	}
	v4 := iptRules(p, false)
	want4 := []string{
		"*nat",
		":ODDLYPROXIFIER - [0:0]",
		"-A ODDLYPROXIFIER -m mark --mark 0x4f44 -j RETURN",
		"-A ODDLYPROXIFIER -d 198.18.0.0/15 -p tcp -j REDIRECT --to-ports 39999",
		"-A ODDLYPROXIFIER ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-ports 39953",
		"-A ODDLYPROXIFIER -d 224.0.0.0/4 -j RETURN", // widest first
		"-A ODDLYPROXIFIER -d 0.0.0.0/8 -j RETURN",
		"-A ODDLYPROXIFIER -d 10.0.0.0/8 -j RETURN",
		"-A ODDLYPROXIFIER -d 127.0.0.0/8 -j RETURN",
		"-A ODDLYPROXIFIER -d 255.255.255.255/32 -j RETURN",
		"-A ODDLYPROXIFIER -p tcp -j REDIRECT --to-ports 39999",
		"COMMIT",
		"*filter",
		":ODDLYPROXIFIER - [0:0]",
		"-A ODDLYPROXIFIER -m mark --mark 0x4f44 -j RETURN",
		"-A ODDLYPROXIFIER -d 224.0.0.0/4 -j RETURN", // widest first
		"-A ODDLYPROXIFIER -d 0.0.0.0/8 -j RETURN",
		"-A ODDLYPROXIFIER -d 10.0.0.0/8 -j RETURN",
		"-A ODDLYPROXIFIER -d 127.0.0.0/8 -j RETURN",
		"-A ODDLYPROXIFIER -d 255.255.255.255/32 -j RETURN",
		"-A ODDLYPROXIFIER -p udp --dport 443 -j REJECT",
		"COMMIT",
	}
	if got := lines(v4); strings.Join(got, "\n") != strings.Join(want4, "\n") {
		t.Errorf("IPv4 rules:\n%s\nwant:\n%s", v4, strings.Join(want4, "\n"))
	}

	v6 := iptRules(p, true)
	for _, want := range []string{
		"-A ODDLYPROXIFIER ! -d ::1/128 -p udp --dport 53 -j REDIRECT --to-ports 39953",
		"-A ODDLYPROXIFIER -d fd00::/8 -j RETURN",
		"-A ODDLYPROXIFIER -d ::1/128 -j RETURN",
		"-A ODDLYPROXIFIER -p tcp -j REDIRECT --to-ports 39999",
	} {
		if !strings.Contains(v6, want+"\n") {
			t.Errorf("IPv6 rules lack %q:\n%s", want, v6)
		}
	}
	for _, unwanted := range []string{"198.18.", "10.0.0.0", "127.0.0.0"} {
		if strings.Contains(v6, unwanted) {
			t.Errorf("IPv4 network %q in the IPv6 rules:\n%s", unwanted, v6)
		}
	}

	// Without QUIC blocking the filter chain is still declared, and empty:
	// that is what flushes the rules of an earlier run.
	plain := iptRules(Policy{Port: 39999, TargetPort: 8443}, false)
	if !strings.HasSuffix(plain, "COMMIT\n*filter\n:ODDLYPROXIFIER - [0:0]\nCOMMIT\n") {
		t.Errorf("filter table without QUIC blocking:\n%s", plain)
	}
	if !strings.Contains(plain, "-A ODDLYPROXIFIER -p tcp --dport 8443 -j REDIRECT --to-ports 39999\n") {
		t.Errorf("single-port mode:\n%s", plain)
	}
}

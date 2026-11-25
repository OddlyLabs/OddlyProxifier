package ppx

import (
	"strings"
	"testing"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/rules"
)

const sample = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ProxifierProfile version="101" platform="Windows" product_id="0" product_minver="310">
  <Options>
    <Resolve>
      <AutoModeDetection enabled="false" />
      <ViaProxy enabled="true"><TryLocalDnsFirst enabled="false" /></ViaProxy>
      <ExclusionList>%ComputerName%; localhost; *.local; *.corp.example</ExclusionList>
    </Resolve>
  </Options>
  <ProxyList>
    <Proxy id="100" type="SOCKS5">
      <Address>10.0.0.8</Address><Port>1080</Port><Options>48</Options>
      <Authentication enabled="true"><Username>alice</Username><Password>AAAB6x==</Password></Authentication>
    </Proxy>
    <Proxy id="101" type="HTTPS"><Address>proxy.example.com</Address><Port>3128</Port><Options>482</Options></Proxy>
    <Proxy id="102" type="SOCKS4"><Address>10.0.0.9</Address><Port>1081</Port></Proxy>
    <Proxy id="103" type="GOPHER"><Address>10.0.0.10</Address><Port>70</Port></Proxy>
  </ProxyList>
  <ChainList>
    <Chain id="200" type="simple"><Name>Two hops</Name><Proxy enabled="true">100</Proxy><Proxy enabled="true">101</Proxy></Chain>
    <Chain id="201" type="redundancy"><Name>Spare</Name><Proxy enabled="true">100</Proxy><Proxy enabled="false">101</Proxy><Proxy enabled="true">102</Proxy></Chain>
    <Chain id="202" type="load_balancing"><Name>Spread</Name><Proxy enabled="true">101</Proxy><Proxy enabled="true">102</Proxy></Chain>
    <Chain id="203" type="simple"><Name>Broken</Name><Proxy enabled="true">103</Proxy></Chain>
  </ChainList>
  <RuleList>
    <Rule enabled="true"><Name>Localhost</Name><Targets>localhost; 127.0.0.1; %ComputerName%; ::1</Targets><Action type="Direct" /></Rule>
    <Rule enabled="true"><Name>Browsers</Name><Applications>chrome.exe; "C:\Program Files\Mozilla Firefox\firefox.exe"</Applications><Ports>80; 443; 8000-9000</Ports><Action type="Proxy">100</Action></Rule>
    <Rule enabled="false"><Name>Office</Name><Targets>192.168.*.*; 10.1.2.*; 172.16.0.1-172.16.0.99; *.example.org</Targets><Action type="Chain">200</Action></Rule>
    <Rule enabled="true"><Name>Ads</Name><Targets>*.ads.example</Targets><Action type="Block" /></Rule>
    <Rule enabled="true"><Name>Via spare</Name><Applications>git.exe</Applications><Action type="Proxy">201</Action></Rule>
    <Rule enabled="true"><Name>Lost</Name><Applications>old.exe</Applications><Action type="Proxy">103</Action></Rule>
    <Rule enabled="true"><Name>Default</Name><Action type="Chain">202</Action></Rule>
  </RuleList>
</ProxifierProfile>`

func TestImport(t *testing.T) {
	if !Looks([]byte(sample)) || Looks([]byte(`{"version":1}`)) {
		t.Fatal("Looks is wrong")
	}
	p, notes, err := Import([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Proxies) != 3 {
		t.Fatalf("proxies: %+v", p.Proxies)
	}
	if x := p.Proxies[0]; x.Type != config.TypeSOCKS5 || x.Host != "10.0.0.8" || x.Port != 1080 || x.Username != "alice" || x.Password != "" {
		t.Errorf("first proxy: %+v", x)
	}
	if p.Proxies[1].Type != config.TypeHTTP || p.Proxies[2].Type != config.TypeSOCKS4A {
		t.Errorf("proxy types: %s %s", p.Proxies[1].Type, p.Proxies[2].Type)
	}
	if len(p.Chains) != 3 {
		t.Fatalf("chains: %+v", p.Chains)
	}
	if c := p.Chains[1]; c.Type != config.ChainFailover || len(c.Proxies) != 2 || c.Proxies[1] != p.Proxies[2].ID {
		t.Errorf("failover chain: %+v", c)
	}
	if p.Chains[2].Type != config.ChainBalance {
		t.Errorf("balance chain: %+v", p.Chains[2])
	}
	if len(p.Rules) != 5 {
		t.Fatalf("rules: %+v", p.Rules)
	}
	if r := p.Rules[1]; r.Ports != "80,443,8000-9000" || len(r.Apps) != 2 ||
		r.Apps[1] != `C:\Program Files\Mozilla Firefox\firefox.exe` || r.Action.Target != p.Proxies[0].ID {
		t.Errorf("browser rule: %+v", r)
	}
	if r := p.Rules[2]; r.Enabled || strings.Join(r.Hosts, " ") != "192.168.0.0/16 10.1.2.0/24 172.16.0.1-172.16.0.99 *.example.org" ||
		r.Action.Type != config.ActionChain {
		t.Errorf("office rule: %+v", r)
	}
	if r := p.Rules[4]; r.Action.Type != config.ActionChain || r.Action.Target != p.Chains[1].ID {
		t.Errorf("a Proxy action that names a chain: %+v", r)
	}
	if p.Default.Type != config.ActionChain || p.Default.Target != p.Chains[2].ID {
		t.Errorf("default: %+v", p.Default)
	}
	if p.DNS.Mode != config.DNSAuto || strings.Join(p.DNS.LocalNames, " ") != "localhost *.local *.corp.example" {
		t.Errorf("dns: %+v", p.DNS)
	}
	joined := strings.Join(notes, "\n")
	for _, want := range []string{"GOPHER", "password", `"Broken"`, `"Lost"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes lack %q:\n%s", want, joined)
		}
	}
	// What was imported must be usable as it is.
	set, err := rules.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if name, a := set.Match(rules.Request{App: `C:\x\chrome.exe`, Host: "example.com", Port: 443}); name != "Browsers" || a.Type != config.ActionProxy {
		t.Errorf("match: %s %+v", name, a)
	}
}

func TestImportRejectsOtherXML(t *testing.T) {
	if _, _, err := Import([]byte("<html></html>")); err == nil {
		t.Error("accepted HTML")
	}
	if _, _, err := Import([]byte("not xml")); err == nil {
		t.Error("accepted text")
	}
}

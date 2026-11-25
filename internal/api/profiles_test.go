package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/engine"
	"oddlyproxifier/internal/profiles"
)

func TestSavedProfiles(t *testing.T) {
	c := start(t)
	var list struct {
		Active string          `json:"active"`
		List   []profiles.Info `json:"list"`
	}
	if resp, _ := c.do("GET", "/api/profiles", nil, &list); resp.StatusCode != 200 || len(list.List) != 0 || list.Active != "" {
		t.Fatalf("empty store: %d %+v", resp.StatusCode, list)
	}

	// "Work": one proxy, everything through it.
	p := c.eng.Profile()
	p.Proxies = []config.Proxy{{ID: "a", Name: "A", Type: "socks5", Host: "10.0.0.1", Port: 1080, Password: "secret"}}
	p.Default = config.Action{Type: config.ActionProxy, Target: "a"}
	if resp, body := c.do("PUT", "/api/profile", p, nil); resp.StatusCode != 200 {
		t.Fatal(body)
	}
	if resp, body := c.do("PUT", "/api/profiles/Work", nil, &list); resp.StatusCode != 200 || list.Active != "Work" || len(list.List) != 1 {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	if list.List[0].Proxies != 1 {
		t.Errorf("info: %+v", list.List[0])
	}
	// The stored file carries no token and no ports.
	raw, err := os.ReadFile(filepath.Join(profiles.For(c.eng.Path()).Dir(), "Work.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) || strings.Contains(string(raw), `"options"`) || !strings.Contains(string(raw), "secret") {
		t.Errorf("stored profile:\n%s", raw)
	}

	// "Home": direct. Then back to "Work".
	p = c.eng.Profile()
	p.Default = config.Action{Type: config.ActionDirect}
	p.Proxies = nil
	c.do("PUT", "/api/profile", p, nil)
	c.do("PUT", "/api/profiles/Home", nil, &list)
	if list.Active != "Home" || len(list.List) != 2 {
		t.Fatalf("after Home: %+v", list)
	}
	inbound := c.eng.Profile().Options.Inbound
	var got config.Profile
	if resp, body := c.do("POST", "/api/profiles/Work/activate", nil, &got); resp.StatusCode != 200 {
		t.Fatal(body)
	}
	if got.Name != "Work" || len(got.Proxies) != 1 || got.Proxies[0].Password != "secret" || got.Default.Target != "a" {
		t.Errorf("activated: %+v", got)
	}
	if got.Options.Inbound != inbound || got.Options.APIToken != token {
		t.Errorf("machine options changed: %+v", got.Options)
	}

	for _, bad := range []string{"..", "a%2Fb", "CON", "x%3Ay"} {
		if resp, _ := c.do("PUT", "/api/profiles/"+bad, nil, nil); resp.StatusCode != http.StatusUnprocessableEntity && resp.StatusCode != http.StatusNotFound {
			t.Errorf("name %q: status %d", bad, resp.StatusCode)
		}
	}
	if resp, _ := c.do("POST", "/api/profiles/Nope/activate", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("activate unknown: %d", resp.StatusCode)
	}
	if resp, _ := c.do("DELETE", "/api/profiles/Work", nil, &list); resp.StatusCode != 200 || len(list.List) != 1 || list.Active != "" {
		t.Errorf("delete: %d %+v", resp.StatusCode, list)
	}
}

func TestExportImport(t *testing.T) {
	c := start(t)
	p := c.eng.Profile()
	p.Proxies = []config.Proxy{{ID: "a", Name: "A", Type: "socks5", Host: "10.0.0.1", Port: 1080, Username: "u", Password: "secret"}}
	p.Rules = append(p.Rules, config.Rule{ID: "r", Name: "R", Enabled: true, Apps: []string{"x.exe"},
		Action: config.Action{Type: config.ActionProxy, Target: "a"}})
	c.do("PUT", "/api/profile", p, nil)

	_, plain := c.do("GET", "/api/export", nil, nil)
	if strings.Contains(plain, "secret") || strings.Contains(plain, token) || !strings.Contains(plain, `"x.exe"`) {
		t.Errorf("export without passwords:\n%s", plain)
	}
	_, full := c.do("GET", "/api/export?passwords=1", nil, nil)
	if !strings.Contains(full, "secret") || strings.Contains(full, token) {
		t.Errorf("export with passwords:\n%s", full)
	}

	// Wipe, then bring it back from the export.
	empty := c.eng.Profile()
	empty.Proxies, empty.Rules = nil, nil
	c.do("PUT", "/api/profile", empty, nil)
	var out struct {
		Profile config.Profile `json:"profile"`
		Notes   []string       `json:"notes"`
	}
	if resp, body := c.do("POST", "/api/import?name=Restored", full, &out); resp.StatusCode != 200 {
		t.Fatal(body)
	}
	if out.Profile.Name != "Restored" || len(out.Profile.Proxies) != 1 || out.Profile.Proxies[0].Password != "secret" || len(out.Profile.Rules) != 2 {
		t.Errorf("imported: %+v", out.Profile)
	}
	if out.Profile.Options.APIToken != token {
		t.Error("the token changed")
	}
	if _, err := profiles.For(c.eng.Path()).Load("Restored"); err != nil {
		t.Error(err)
	}

	ppxFile := `<ProxifierProfile version="101"><ProxyList><Proxy id="1" type="SOCKS5"><Address>10.9.9.9</Address><Port>1080</Port>
<Authentication enabled="true"><Username>bob</Username><Password>xx</Password></Authentication></Proxy></ProxyList>
<RuleList><Rule enabled="true"><Name>All</Name><Applications>curl.exe</Applications><Action type="Proxy">1</Action></Rule>
<Rule enabled="true"><Name>Default</Name><Action type="Direct"/></Rule></RuleList></ProxifierProfile>`
	if resp, body := c.do("POST", "/api/import", ppxFile, &out); resp.StatusCode != 200 {
		t.Fatal(body)
	}
	if len(out.Profile.Proxies) != 1 || out.Profile.Proxies[0].Host != "10.9.9.9" || len(out.Profile.Rules) != 1 || len(out.Notes) != 1 {
		t.Errorf("ppx import: %+v notes %v", out.Profile, out.Notes)
	}

	for _, bad := range []string{"{}", "hello", `{"rules":[{"name":"x","action":{"type":"proxy","target":"gone"}}]}`} {
		if resp, _ := c.do("POST", "/api/import", bad, nil); resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("import %q: status %d", bad, resp.StatusCode)
		}
	}
}

func TestTraffic(t *testing.T) {
	c := start(t)
	var tr engine.Traffic
	if resp, body := c.do("GET", "/api/traffic", nil, &tr); resp.StatusCode != 200 || tr.Apps == nil || tr.Points == nil {
		t.Fatalf("traffic: %d %s", resp.StatusCode, body)
	}
	if resp, _ := c.do("DELETE", "/api/traffic", nil, nil); resp.StatusCode != 200 {
		t.Errorf("reset: %d", resp.StatusCode)
	}
}

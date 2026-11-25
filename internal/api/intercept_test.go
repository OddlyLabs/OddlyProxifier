package api

import (
	"net/http"
	"testing"

	"oddlyproxifier/internal/engine"
)

func TestInterceptSwitch(t *testing.T) {
	c := start(t)
	before := c.eng.Profile()
	var st engine.Status
	if resp, body := c.do("POST", "/api/intercept", map[string]bool{"enabled": true}, &st); resp.StatusCode != 200 || !st.Intercept.Enabled {
		t.Fatalf("on: %d %s", resp.StatusCode, body)
	}
	after := c.eng.Profile()
	if !after.Options.Intercept || after.Options.Inbound != before.Options.Inbound || len(after.Rules) != len(before.Rules) {
		t.Errorf("the switch changed more than itself: %+v", after.Options)
	}
	if resp, _ := c.do("POST", "/api/intercept", map[string]bool{"enabled": false}, &st); resp.StatusCode != 200 || st.Intercept.Enabled {
		t.Errorf("off: %d %+v", resp.StatusCode, st.Intercept)
	}
	for _, bad := range []string{"{}", "nonsense", `{"enabled":"yes"}`} {
		if resp, _ := c.do("POST", "/api/intercept", bad, nil); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %q: status %d", bad, resp.StatusCode)
		}
	}
}

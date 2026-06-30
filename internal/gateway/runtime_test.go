package gateway

import (
	"testing"

	"aegis-waf/internal/database"
)

func TestRuntimeMatchesNormalizedHost(t *testing.T) {
	site := database.Site{ID: 1, Name: "test", Upstream: "http://127.0.0.1:8081", Status: database.SiteStatusEnabled, WAFEnabled: true}
	if err := site.SetDomains([]string{"test.local"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := BuildSnapshot([]database.Site{site})
	if err != nil {
		t.Fatal(err)
	}
	manager := &RuntimeManager{}
	manager.value.Store(snapshot)
	if got, ok := manager.MatchSite("test.local"); !ok || got.ID != 1 {
		t.Fatalf("test.local did not match: %#v %v", got, ok)
	}
	if got, ok := manager.MatchSite("test.local:9090"); !ok || got.ID != 1 {
		t.Fatalf("host with port did not match: %#v %v", got, ok)
	}
	if _, ok := manager.MatchSite("missing.local"); ok {
		t.Fatal("unexpected match for missing host")
	}
}

func TestRuntimeCarriesSiteRuleGroupsOnlyForCustomMode(t *testing.T) {
	site := database.Site{ID: 2, Name: "grouped", Upstream: "http://127.0.0.1:8081", Status: database.SiteStatusEnabled, WAFEnabled: true}
	if err := site.SetDomains([]string{"grouped.local"}); err != nil {
		t.Fatal(err)
	}
	if err := site.SetRuleGroups([]string{"sqli", "xss"}); err != nil {
		t.Fatal(err)
	}
	runtimeSite, err := FromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeSite.RuleGroups != nil {
		t.Fatalf("standard runtime rule groups = %#v, want nil", runtimeSite.RuleGroups)
	}

	site.PolicyMode = database.PolicyModeCustom
	runtimeSite, err = FromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtimeSite.RuleGroups) != 2 || runtimeSite.RuleGroups[0] != "sqli" || runtimeSite.RuleGroups[1] != "xss" {
		t.Fatalf("custom runtime rule groups = %#v, want sqli/xss", runtimeSite.RuleGroups)
	}
}

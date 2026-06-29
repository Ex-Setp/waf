package accesscontrol

import (
	"net"
	"testing"

	"aegis-waf/internal/database"
)

func TestEvaluatorAccessRules(t *testing.T) {
	rules := []database.AccessRule{{SiteID: 1, Type: database.AccessRuleIPBlacklist, Value: "203.0.113.10", Enabled: true}, {SiteID: 1, Type: database.AccessRuleIPWhitelist, Value: "198.51.100.0/24", Enabled: true}, {SiteID: 1, Type: database.AccessRuleURLWhitelist, Value: "/health*", Enabled: true}, {SiteID: 1, Type: database.AccessRuleUABlacklist, Value: "badbot", Enabled: true}}
	e := NewEvaluator(rules)
	if got := e.Evaluate(Request{SiteID: 1, SourceIP: net.ParseIP("203.0.113.10")}); got.Decision != DecisionBlock {
		t.Fatalf("ip blacklist=%s", got.Decision)
	}
	if got := e.Evaluate(Request{SiteID: 1, SourceIP: net.ParseIP("198.51.100.9")}); got.Decision != DecisionSkipDetection {
		t.Fatalf("ip whitelist=%s", got.Decision)
	}
	if got := e.Evaluate(Request{SiteID: 1, Path: "/healthz"}); got.Decision != DecisionAllow {
		t.Fatalf("url whitelist=%s", got.Decision)
	}
	if got := e.Evaluate(Request{SiteID: 1, UserAgent: "BadBot/1.0"}); got.Decision != DecisionBlock {
		t.Fatalf("ua blacklist=%s", got.Decision)
	}
}

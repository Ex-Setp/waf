package detection

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"aegis-waf/internal/crs"
)

func TestCorazaEngineBlocksCRSMatch(t *testing.T) {
	dir := t.TempDir()
	writeTestCRS(t, dir, `SecRule ARGS "@contains union" "id:942100,phase:2,deny,log,msg:'SQLi probe',severity:'CRITICAL',tag:'attack-sqli'"`)
	manager := crs.NewManager(crs.Config{Enabled: true, RulesDir: dir, InboundThreshold: 5, RequestBodyLimit: 1024})
	engine, err := NewCorazaEngine(manager)
	if err != nil {
		t.Fatalf("NewCorazaEngine returned error: %v", err)
	}
	result, err := engine.Inspect(context.Background(), Request{Method: http.MethodGet, URI: "/search?q=union", Headers: http.Header{"Host": []string{"example.test"}}, Args: map[string][]string{"q": {"union"}}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock || len(result.Matches) == 0 {
		t.Fatalf("expected CRS block match, got %+v", result)
	}
	if result.Matches[0].Source != "crs" || result.Matches[0].ID != 942100 {
		t.Fatalf("unexpected match: %+v", result.Matches[0])
	}
}

func TestCompositeEngineDelegatesRuntimeRules(t *testing.T) {
	manager, err := NewManager("", nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	engine := NewCompositeEngine(nil, manager, true)
	if err := engine.UpsertRuntimeRule(Rule{ID: 991001, Variable: "ARGS", Operator: "@contains", Pattern: "probe", Action: RuleActionDeny, Message: "probe", Severity: "high", Score: 5, Source: "custom", Enabled: true}); err != nil {
		t.Fatalf("UpsertRuntimeRule returned error: %v", err)
	}
	result, err := engine.Inspect(context.Background(), Request{Method: http.MethodGet, URI: "/?q=probe", Args: map[string][]string{"q": {"probe"}}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock || len(result.Matches) != 1 || result.Matches[0].Source != "custom" {
		t.Fatalf("unexpected composite result: %+v", result)
	}
}

func writeTestCRS(t *testing.T, dir, rule string) {
	t.Helper()
	content := "SecRuleEngine On\n" + rule + "\n"
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-942-test.conf"), []byte(content), 0o600); err != nil {
		t.Fatalf("write CRS file: %v", err)
	}
}

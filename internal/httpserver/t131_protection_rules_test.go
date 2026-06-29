package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestProtectionRuleCRUDHotReloadAndAudit(t *testing.T) {
	db := testDB(t)
	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	body := `{"ruleId":991001,"name":"block probe","category":"custom","variable":"ARGS","operator":"@contains","pattern":"probe_token","action":"deny","severity":"high","score":9,"source":"custom","enabled":true}`
	create := httptest.NewRecorder()
	server.Handler().ServeHTTP(create, httptest.NewRequest(http.MethodPost, "/api/protection/rules", strings.NewReader(body)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}

	blocked, err := processor.Process(context.Background(), pipeline.Request{Path: "/search?q=probe_token", Args: map[string][]string{"q": {"probe_token"}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process after create: %v", err)
	}
	if blocked.Decision != pipeline.DecisionBlock || blocked.Detection.Score != 9 || blocked.BlockedByStage != pipeline.StageDetection {
		t.Fatalf("expected created deny rule to block with score 9, got %+v", blocked)
	}

	disable := httptest.NewRecorder()
	server.Handler().ServeHTTP(disable, httptest.NewRequest(http.MethodPost, "/api/protection/rules/1/disable", nil))
	if disable.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", disable.Code, disable.Body.String())
	}
	allowed, err := processor.Process(context.Background(), pipeline.Request{Path: "/search?q=probe_token", Args: map[string][]string{"q": {"probe_token"}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process after disable: %v", err)
	}
	if allowed.Decision != pipeline.DecisionAllow || len(allowed.Detection.Matches) != 0 {
		t.Fatalf("expected disabled rule to allow, got %+v", allowed)
	}

	update := httptest.NewRecorder()
	server.Handler().ServeHTTP(update, httptest.NewRequest(http.MethodPut, "/api/protection/rules/1", strings.NewReader(`{"ruleId":991001,"name":"observe probe","category":"custom","variable":"ARGS","operator":"@contains","pattern":"probe_token","action":"log","severity":"low","score":2,"source":"custom","enabled":true}`)))
	if update.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", update.Code, update.Body.String())
	}
	observed, err := processor.Process(context.Background(), pipeline.Request{Path: "/search?q=probe_token", Args: map[string][]string{"q": {"probe_token"}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process after update: %v", err)
	}
	if observed.Decision != pipeline.DecisionAllow || observed.Detection.Score != 2 || len(observed.Detection.Matches) != 1 || observed.Detection.Matches[0].Action != detection.RuleActionLog {
		t.Fatalf("expected log action score 2 to observe, got %+v", observed)
	}

	var audits []database.AuditEvent
	if err := db.Where("type = ? AND resource = ?", "protection_rule", "rule:991001").Find(&audits).Error; err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if len(audits) < 3 {
		t.Fatalf("expected create/disable/update audit events, got %+v", audits)
	}

	list := httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/protection/rules", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "custom") || !strings.Contains(list.Body.String(), "991001") {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
}

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

func TestT132SemanticFingerprintPromoteRuleRuntimeAndRollback(t *testing.T) {
	db := testDB(t)
	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	payload := "select name from users union select password from secrets"
	fp := database.SemanticFingerprint{Hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Language: "sql", Skeleton: "(select (union))", SamplePayload: payload, Action: "log", Status: database.SemanticFingerprintStatusObserving, Hits: 4, Source: "semantic-detection", XDPSyncStatus: "not_required"}
	if err := db.Create(&fp).Error; err != nil {
		t.Fatalf("seed fingerprint: %v", err)
	}

	promote := httptest.NewRecorder()
	server.Handler().ServeHTTP(promote, httptest.NewRequest(http.MethodPost, "/api/semantic-fingerprints/1/promote-rule", nil))
	if promote.Code != http.StatusOK {
		t.Fatalf("promote status=%d body=%s", promote.Code, promote.Body.String())
	}

	var rule database.ProtectionRule
	if err := db.Where("source = ? AND category = ?", "semantic", "semantic").First(&rule).Error; err != nil {
		t.Fatalf("semantic rule not persisted: %v", err)
	}
	if rule.RuleID == 0 || rule.Action != "deny" || rule.Pattern != payload || !rule.Enabled {
		t.Fatalf("unexpected promoted rule: %#v", rule)
	}

	blocked, err := processor.Process(context.Background(), pipeline.Request{Path: "/search", Args: map[string][]string{"q": {payload}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process after promote: %v", err)
	}
	if blocked.Decision != pipeline.DecisionBlock || blocked.BlockedByStage != pipeline.StageDetection || blocked.Detection.Score < 8 {
		t.Fatalf("expected promoted semantic rule to block, got %+v", blocked)
	}

	listRules := httptest.NewRecorder()
	server.Handler().ServeHTTP(listRules, httptest.NewRequest(http.MethodGet, "/api/protection/rules", nil))
	if listRules.Code != http.StatusOK || !strings.Contains(listRules.Body.String(), "semantic") || !strings.Contains(listRules.Body.String(), payload) {
		t.Fatalf("promoted rule not visible in protection rules: status=%d body=%s", listRules.Code, listRules.Body.String())
	}

	rollback := httptest.NewRecorder()
	server.Handler().ServeHTTP(rollback, httptest.NewRequest(http.MethodPost, "/api/semantic-fingerprints/1/rollback", nil))
	if rollback.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollback.Code, rollback.Body.String())
	}
	var count int64
	if err := db.Model(&database.ProtectionRule{}).Where("rule_id = ?", rule.RuleID).Count(&count).Error; err != nil {
		t.Fatalf("count rules after rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected semantic rule removed on rollback, got count=%d", count)
	}

	allowed, err := processor.Process(context.Background(), pipeline.Request{Path: "/search", Args: map[string][]string{"q": {payload}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process after rollback: %v", err)
	}
	if allowed.Decision != pipeline.DecisionAllow || len(allowed.Detection.Matches) != 0 {
		t.Fatalf("expected rollback to remove runtime rule, got %+v", allowed)
	}

	var audits []database.AuditEvent
	if err := db.Where("type IN ?", []string{"semantic_fingerprint", "protection_rule"}).Find(&audits).Error; err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if len(audits) < 3 {
		t.Fatalf("expected semantic promote/rollback and protection promote audits, got %+v", audits)
	}
}

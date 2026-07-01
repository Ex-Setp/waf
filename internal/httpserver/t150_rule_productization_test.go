package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

type t150ProtectionRuleExportResponse struct {
	Rules []database.ProtectionRule `json:"rules"`
	Total int                       `json:"total"`
}

func decodeT150ProtectionRuleExportResponse(t *testing.T, body []byte) t150ProtectionRuleExportResponse {
	t.Helper()

	var envelope t150ProtectionRuleExportResponse
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Rules != nil {
		if envelope.Total == 0 {
			envelope.Total = len(envelope.Rules)
		}
		return envelope
	}

	var rules []database.ProtectionRule
	if err := json.Unmarshal(body, &rules); err != nil {
		t.Fatalf("decode export: %v body=%s", err, string(body))
	}
	return t150ProtectionRuleExportResponse{Rules: rules, Total: len(rules)}
}

func TestT150InvalidImportDoesNotPolluteRuntimeOrDB(t *testing.T) {
	db := testDB(t)
	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	create := httptest.NewRecorder()
	server.Handler().ServeHTTP(create, httptest.NewRequest(http.MethodPost, "/api/protection/rules", strings.NewReader(`{"ruleId":150001,"name":"baseline","category":"custom","variable":"ARGS","operator":"@contains","pattern":"t150_keep","action":"deny","severity":"high","score":7,"source":"custom","enabled":true}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", create.Code, create.Body.String())
	}

	importBody := `[{"ruleId":150002,"name":"bad","category":"custom","variable":"UNKNOWN","operator":"@contains","pattern":"x","action":"deny","severity":"high","score":7,"source":"custom","enabled":true}]`
	importRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(importRec, httptest.NewRequest(http.MethodPost, "/api/protection/rules/import", strings.NewReader(importBody)))
	if importRec.Code != http.StatusBadRequest {
		t.Fatalf("import=%d %s", importRec.Code, importRec.Body.String())
	}
	var validation protectionRuleImportResponse
	if err := json.Unmarshal(importRec.Body.Bytes(), &validation); err != nil {
		t.Fatalf("decode import validation: %v body=%s", err, importRec.Body.String())
	}
	if validation.Valid {
		t.Fatalf("expected invalid import response, got %+v", validation)
	}
	if len(validation.Errors) == 0 || validation.Errors[0].Field == "" {
		t.Fatalf("expected fielded validation errors, got %+v", validation.Errors)
	}

	var count int64
	if err := db.Model(&database.ProtectionRule{}).Count(&count).Error; err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected db unchanged, count=%d", count)
	}

	result, err := processor.Process(context.Background(), pipeline.Request{Path: "/?q=t150_keep", Args: map[string][]string{"q": {"t150_keep"}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if result.Decision != pipeline.DecisionBlock {
		t.Fatalf("expected baseline runtime rule still active, got %+v", result)
	}
}

func TestT150ImportExportRollbackAndAudit(t *testing.T) {
	db := testDB(t)
	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	create := httptest.NewRecorder()
	server.Handler().ServeHTTP(create, httptest.NewRequest(http.MethodPost, "/api/protection/rules", strings.NewReader(`{"ruleId":150010,"name":"old rule","category":"custom","variable":"ARGS","operator":"@contains","pattern":"t150_old","action":"deny","severity":"high","score":9,"source":"custom","enabled":true}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", create.Code, create.Body.String())
	}

	importBody := `[{"ruleId":150011,"name":"new observe","category":"custom","variable":"ARGS","operator":"@contains","pattern":"t150_new","action":"log","severity":"low","score":2,"source":"custom","enabled":true}]`
	importRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(importRec, httptest.NewRequest(http.MethodPost, "/api/protection/rules/import", strings.NewReader(importBody)))
	if importRec.Code != http.StatusOK {
		t.Fatalf("import=%d %s", importRec.Code, importRec.Body.String())
	}

	exportRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(exportRec, httptest.NewRequest(http.MethodGet, "/api/protection/rules/export", nil))
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export=%d %s", exportRec.Code, exportRec.Body.String())
	}
	exported := decodeT150ProtectionRuleExportResponse(t, exportRec.Body.Bytes())
	if exported.Total != 1 || len(exported.Rules) != 1 || exported.Rules[0].RuleID != 150011 {
		t.Fatalf("unexpected export: %+v", exported)
	}

	observed, err := processor.Process(context.Background(), pipeline.Request{Path: "/?q=t150_new", Args: map[string][]string{"q": {"t150_new"}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process new: %v", err)
	}
	if observed.Decision != pipeline.DecisionAllow || observed.Detection.Score != 2 {
		t.Fatalf("expected imported log rule to observe, got %+v", observed)
	}

	rollbackRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rollbackRec, httptest.NewRequest(http.MethodPost, "/api/protection/rules/rollback", nil))
	if rollbackRec.Code != http.StatusOK {
		t.Fatalf("rollback=%d %s", rollbackRec.Code, rollbackRec.Body.String())
	}

	restored, err := processor.Process(context.Background(), pipeline.Request{Path: "/?q=t150_old", Args: map[string][]string{"q": {"t150_old"}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process restored: %v", err)
	}
	if restored.Decision != pipeline.DecisionBlock {
		t.Fatalf("expected rollback restored old blocking rule, got %+v", restored)
	}
	afterRollback, err := processor.Process(context.Background(), pipeline.Request{Path: "/?q=t150_new", Args: map[string][]string{"q": {"t150_new"}}, BlockScoreThreshold: 5})
	if err != nil {
		t.Fatalf("process after rollback: %v", err)
	}
	if afterRollback.Decision != pipeline.DecisionAllow || len(afterRollback.Detection.Matches) != 0 {
		t.Fatalf("expected imported rule removed after rollback, got %+v", afterRollback)
	}

	var audits []database.AuditEvent
	if err := db.Where("type = ? AND action IN ?", "protection_rule", []string{"import", "rollback"}).Find(&audits).Error; err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if len(audits) < 2 {
		t.Fatalf("expected import and rollback audits, got %+v", audits)
	}
}

func TestT150RuleListIncludesHitStatistics(t *testing.T) {
	db := testDB(t)
	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	if err := db.Create(&database.ProtectionRule{RuleID: 150020, Name: "hits", Category: "custom", Variable: "ARGS", Operator: "@contains", Pattern: "hits", Action: "deny", Severity: "high", Score: 7, Source: "custom", Enabled: true}).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if err := server.reloadProtectionRules(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := db.Create(&[]database.AttackLog{{RuleID: "150020"}, {RuleID: "150020"}}).Error; err != nil {
		t.Fatalf("seed attacks: %v", err)
	}

	list := httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/protection/rules", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list=%d %s", list.Code, list.Body.String())
	}
	if !strings.Contains(list.Body.String(), `"hits":2`) {
		t.Fatalf("expected hit statistics in list: %s", list.Body.String())
	}
}

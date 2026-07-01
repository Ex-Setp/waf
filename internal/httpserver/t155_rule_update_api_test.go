package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"

	"gorm.io/gorm"
)

func TestT155RuleUpdatePublishAndHashRejection(t *testing.T) {
	db := testDB(t)
	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	seedT155Rule(t, db, server, database.ProtectionRule{
		RuleID:   155001,
		Name:     "baseline block",
		Category: "custom",
		Variable: "ARGS",
		Operator: "@contains",
		Pattern:  "t155-baseline",
		Action:   "deny",
		Severity: "high",
		Score:    9,
		Source:   "custom",
		Enabled:  true,
	})

	published := postT155JSON(t, server, "/api/protection/rule-updates/publish", fmt.Sprintf(`{
		"expectedHash": %q,
		"package": {
			"type": "manual",
			"version": "t155-v1",
			"hash": %q,
			"mode": "block",
			"rules": [{
				"ruleId": 155002,
				"name": "candidate block",
				"category": "custom",
				"variable": "ARGS",
				"operator": "@contains",
				"pattern": "t155-candidate",
				"action": "deny",
				"severity": "high",
				"score": 9,
				"source": "custom",
				"enabled": true
			}]
		}
	}`, t155ExpectedHash(database.ProtectionRule{
		RuleID:   155002,
		Name:     "candidate block",
		Category: "custom",
		Variable: "ARGS",
		Operator: "@contains",
		Pattern:  "t155-candidate",
		Action:   "deny",
		Severity: "high",
		Score:    9,
		Source:   "custom",
		Enabled:  true,
	}), t155ExpectedHash(database.ProtectionRule{
		RuleID:   155002,
		Name:     "candidate block",
		Category: "custom",
		Variable: "ARGS",
		Operator: "@contains",
		Pattern:  "t155-candidate",
		Action:   "deny",
		Severity: "high",
		Score:    9,
		Source:   "custom",
		Enabled:  true,
	})))
	if published.Code != http.StatusOK {
		t.Fatalf("publish=%d %s", published.Code, published.Body.String())
	}
	var publishLog ruleUpdateLogResponse
	decodeT155JSON(t, published.Body.Bytes(), &publishLog)
	if publishLog.Status != "published" || !publishLog.Published {
		t.Fatalf("unexpected publish log: %+v", publishLog)
	}
	if publishLog.PackageVersion != "t155-v1" || publishLog.RuleCount != 1 || publishLog.NewRules != 1 {
		t.Fatalf("unexpected publish metadata: %+v", publishLog)
	}

	result, err := processor.Process(context.Background(), pipeline.Request{
		Path:                "/?q=t155-candidate",
		Args:                map[string][]string{"q": {"t155-candidate"}},
		BlockScoreThreshold: 5,
	})
	if err != nil {
		t.Fatalf("process published: %v", err)
	}
	if result.Decision != pipeline.DecisionBlock {
		t.Fatalf("expected candidate block after publish, got %+v", result)
	}

	rejected := postT155JSON(t, server, "/api/protection/rule-updates/publish", `{
		"expectedHash": "bad-hash",
		"package": {
			"type": "manual",
			"version": "t155-bad",
			"mode": "block",
			"rules": [{
				"ruleId": 155003,
				"name": "bad hash rule",
				"category": "custom",
				"variable": "ARGS",
				"operator": "@contains",
				"pattern": "t155-bad-hash",
				"action": "deny",
				"severity": "high",
				"score": 9,
				"source": "custom",
				"enabled": true
			}]
		}
	}`)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("reject=%d %s", rejected.Code, rejected.Body.String())
	}
	if !strings.Contains(rejected.Body.String(), "hash mismatch") {
		t.Fatalf("expected hash mismatch, body=%s", rejected.Body.String())
	}

	var logs []database.ProtectionRuleUpdateLog
	if err := db.Order("id desc").Find(&logs).Error; err != nil {
		t.Fatalf("query logs: %v", err)
	}
	if len(logs) < 2 {
		t.Fatalf("expected publish and rejected logs, got %d", len(logs))
	}
	if logs[0].Status != "rejected" || logs[0].BlockedReason != "hash mismatch" {
		t.Fatalf("unexpected latest rejection log: %+v", logs[0])
	}
}

func TestT155RuleUpdateBlockedObserveEmergencyRollbackAndSummary(t *testing.T) {
	db := testDB(t)
	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	seedT155Rule(t, db, server, database.ProtectionRule{
		RuleID:   155010,
		Name:     "safe baseline",
		Category: "custom",
		Variable: "ARGS",
		Operator: "@contains",
		Pattern:  "t155-safe",
		Action:   "deny",
		Severity: "high",
		Score:    9,
		Source:   "custom",
		Enabled:  true,
	})

	blocked := postT155JSON(t, server, "/api/protection/rule-updates/publish", `{
		"package": {
			"type": "manual",
			"version": "t155-regress",
			"mode": "block",
			"rules": [{
				"ruleId": 155011,
				"name": "false positive deny rule",
				"category": "custom",
				"variable": "ARGS",
				"operator": "@contains",
				"pattern": "customer",
				"action": "deny",
				"severity": "high",
				"score": 100,
				"source": "custom",
				"enabled": true
			}]
		}
	}`)
	if blocked.Code != http.StatusConflict {
		t.Fatalf("blocked=%d %s", blocked.Code, blocked.Body.String())
	}
	var blockedLog ruleUpdateLogResponse
	decodeT155JSON(t, blocked.Body.Bytes(), &blockedLog)
	if blockedLog.Status != "blocked" || blockedLog.Published || blockedLog.BlockedReason == "" {
		t.Fatalf("unexpected blocked log: %+v", blockedLog)
	}

	stillBaseline, err := processor.Process(context.Background(), pipeline.Request{
		Path:                "/?q=t155-safe",
		Args:                map[string][]string{"q": {"t155-safe"}},
		BlockScoreThreshold: 5,
	})
	if err != nil {
		t.Fatalf("process baseline after blocked update: %v", err)
	}
	if stillBaseline.Decision != pipeline.DecisionBlock {
		t.Fatalf("expected baseline rule to remain active, got %+v", stillBaseline)
	}

	observed := postT155JSON(t, server, "/api/protection/rule-updates/publish", `{
		"observeOnly": true,
		"package": {
			"type": "manual",
			"version": "t155-observe",
			"mode": "gray",
			"rules": [{
				"ruleId": 155012,
				"name": "observe rollout",
				"category": "custom",
				"variable": "ARGS",
				"operator": "@contains",
				"pattern": "t155-observe",
				"action": "deny",
				"severity": "high",
				"score": 9,
				"source": "custom",
				"enabled": true
			}]
		}
	}`)
	if observed.Code != http.StatusOK {
		t.Fatalf("observe publish=%d %s", observed.Code, observed.Body.String())
	}
	var observedLog ruleUpdateLogResponse
	decodeT155JSON(t, observed.Body.Bytes(), &observedLog)
	if observedLog.Status != "published" || observedLog.Mode != "observe" || !observedLog.Published {
		t.Fatalf("unexpected observe log: %+v", observedLog)
	}
	if len(observedLog.PublishedRules) != 1 || observedLog.PublishedRules[0].Action != "log" {
		t.Fatalf("expected observe publish to downgrade runtime action to log, got %+v", observedLog.PublishedRules)
	}

	observeResult, err := processor.Process(context.Background(), pipeline.Request{
		Path:                "/?q=t155-observe",
		Args:                map[string][]string{"q": {"t155-observe"}},
		BlockScoreThreshold: 5,
	})
	if err != nil {
		t.Fatalf("process observe rule: %v", err)
	}
	if observeResult.Decision != pipeline.DecisionAllow || observeResult.Detection.Score != 9 || len(observeResult.Detection.Matches) != 1 {
		t.Fatalf("expected observe path to allow with score, got %+v", observeResult)
	}
	if observeResult.Detection.Matches[0].Action != "log" {
		t.Fatalf("expected observe runtime match action=log, got %+v", observeResult.Detection.Matches)
	}

	emergency := postT155JSON(t, server, "/api/protection/rule-updates/emergency", `{
		"cve": "CVE-2026-1550",
		"version": "t155-emergency",
		"rule": {
			"ruleId": 155013,
			"name": "emergency deny",
			"category": "custom",
			"variable": "ARGS",
			"operator": "@contains",
			"pattern": "t155-emergency",
			"action": "deny",
			"severity": "critical",
			"score": 9,
			"source": "custom",
			"enabled": true
		}
	}`)
	if emergency.Code != http.StatusOK {
		t.Fatalf("emergency=%d %s", emergency.Code, emergency.Body.String())
	}
	var emergencyLog ruleUpdateLogResponse
	decodeT155JSON(t, emergency.Body.Bytes(), &emergencyLog)
	if !emergencyLog.Emergency || emergencyLog.EmergencyCVE != "CVE-2026-1550" || emergencyLog.Status != "published" {
		t.Fatalf("unexpected emergency log: %+v", emergencyLog)
	}

	emergencyResult, err := processor.Process(context.Background(), pipeline.Request{
		Path:                "/?q=t155-emergency",
		Args:                map[string][]string{"q": {"t155-emergency"}},
		BlockScoreThreshold: 5,
	})
	if err != nil {
		t.Fatalf("process emergency rule: %v", err)
	}
	if emergencyResult.Decision != pipeline.DecisionBlock {
		t.Fatalf("expected emergency rule to block, got %+v", emergencyResult)
	}

	rolledBack := postT155JSON(t, server, "/api/protection/rule-updates/rollback", "")
	if rolledBack.Code != http.StatusOK {
		t.Fatalf("rollback=%d %s", rolledBack.Code, rolledBack.Body.String())
	}
	var rollbackLog ruleUpdateLogResponse
	decodeT155JSON(t, rolledBack.Body.Bytes(), &rollbackLog)
	if rollbackLog.Status != "rolled-back" || rollbackLog.RolledBackTo != "t155-emergency" {
		t.Fatalf("unexpected rollback log: %+v", rollbackLog)
	}

	restoredObserve, err := processor.Process(context.Background(), pipeline.Request{
		Path:                "/?q=t155-observe",
		Args:                map[string][]string{"q": {"t155-observe"}},
		BlockScoreThreshold: 5,
	})
	if err != nil {
		t.Fatalf("process restored observe: %v", err)
	}
	if restoredObserve.Decision != pipeline.DecisionAllow || restoredObserve.Detection.Score != 9 || len(restoredObserve.Detection.Matches) != 1 {
		t.Fatalf("expected rollback to restore observe ruleset, got %+v", restoredObserve)
	}

	emergencyGone, err := processor.Process(context.Background(), pipeline.Request{
		Path:                "/?q=t155-emergency",
		Args:                map[string][]string{"q": {"t155-emergency"}},
		BlockScoreThreshold: 5,
	})
	if err != nil {
		t.Fatalf("process after rollback: %v", err)
	}
	if emergencyGone.Decision != pipeline.DecisionAllow || len(emergencyGone.Detection.Matches) != 0 {
		t.Fatalf("expected emergency rule removed after rollback, got %+v", emergencyGone)
	}

	summary := httptest.NewRecorder()
	server.Handler().ServeHTTP(summary, httptest.NewRequest(http.MethodGet, "/api/protection/rule-updates", nil))
	if summary.Code != http.StatusOK {
		t.Fatalf("summary=%d %s", summary.Code, summary.Body.String())
	}
	var envelope ruleUpdateSummaryResponse
	decodeT155JSON(t, summary.Body.Bytes(), &envelope)
	if envelope.CurrentRuleCount != 1 || envelope.Latest == nil {
		t.Fatalf("unexpected summary envelope: %+v", envelope)
	}
	if envelope.Latest.Status != "rolled-back" || envelope.Logs[0].Status != "rolled-back" {
		t.Fatalf("expected latest rollback visibility in summary, got %+v", envelope)
	}
	foundBlocked := false
	foundEmergency := false
	for _, log := range envelope.Logs {
		if log.Status == "blocked" && log.BlockedReason != "" {
			foundBlocked = true
		}
		if log.Emergency && log.EmergencyCVE == "CVE-2026-1550" {
			foundEmergency = true
		}
	}
	if !foundBlocked || !foundEmergency {
		t.Fatalf("expected blocked and emergency entries in summary logs, got %+v", envelope.Logs)
	}
}

func TestT155RuleUpdateSourceCreationVisibleInSummary(t *testing.T) {
	db := testDB(t)
	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	created := postT155JSON(t, server, "/api/protection/rule-updates/sources", `{
		"name": "intel-feed",
		"type": "remote",
		"url": "https://example.test/t155.json",
		"mode": "gray",
		"enabled": true,
		"expectedHash": "abc123"
	}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create source=%d %s", created.Code, created.Body.String())
	}
	var sourceResp struct {
		Name           string `json:"name"`
		Type           string `json:"type"`
		URL            string `json:"url"`
		Mode           string `json:"mode"`
		Enabled        bool   `json:"enabled"`
		ExpectedHash   string `json:"expectedHash"`
		CurrentVersion string `json:"currentVersion"`
	}
	decodeT155JSON(t, created.Body.Bytes(), &sourceResp)
	if sourceResp.Name != "intel-feed" || sourceResp.Type != "remote" || sourceResp.Mode != "observe" || !sourceResp.Enabled || sourceResp.ExpectedHash != "abc123" {
		t.Fatalf("unexpected source response: %+v", sourceResp)
	}
	if sourceResp.CurrentVersion != "" {
		t.Fatalf("expected empty currentVersion for new source, got %+v", sourceResp)
	}

	summary := httptest.NewRecorder()
	server.Handler().ServeHTTP(summary, httptest.NewRequest(http.MethodGet, "/api/protection/rule-updates", nil))
	if summary.Code != http.StatusOK {
		t.Fatalf("summary=%d %s", summary.Code, summary.Body.String())
	}
	var envelope ruleUpdateSummaryResponse
	decodeT155JSON(t, summary.Body.Bytes(), &envelope)
	if len(envelope.Sources) != 1 {
		t.Fatalf("expected one source in summary, got %+v", envelope.Sources)
	}
	source := envelope.Sources[0]
	if source.Name != "intel-feed" || source.Type != "remote" || source.URL != "https://example.test/t155.json" {
		t.Fatalf("unexpected summary source: %+v", source)
	}
	if source.Mode != "observe" || !source.Enabled || source.ExpectedHash != "abc123" {
		t.Fatalf("unexpected summary source mode/hash: %+v", source)
	}
}

func seedT155Rule(t *testing.T, db *gorm.DB, server *Server, rule database.ProtectionRule) {
	t.Helper()
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if err := server.reloadProtectionRules(context.Background()); err != nil {
		t.Fatalf("reload rules: %v", err)
	}
}

func postT155JSON(t *testing.T, server *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, reader))
	return rec
}

func decodeT155JSON(t *testing.T, body []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode json: %v body=%s", err, string(body))
	}
}

func t155ExpectedHash(rule database.ProtectionRule) string {
	return protectionRuleSetHash([]database.ProtectionRule{rule})
}

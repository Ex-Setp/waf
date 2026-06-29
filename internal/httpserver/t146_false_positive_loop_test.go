package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/pipeline"
)

func TestT146AttackLogWhitelistUsesMinimalScopeAndValidates(t *testing.T) {
	db := testDB(t)
	log := database.AttackLog{
		SiteID:         11,
		SiteName:       "checkout",
		SourceIP:       "198.51.100.146",
		Method:         http.MethodGet,
		Path:           "/pay/callback?token=t146_probe",
		AttackType:     "SQLi",
		Severity:       "medium",
		Action:         "block",
		FinalAction:    "block",
		Stage:          "detection",
		RuleID:         "146001",
		RuleMessage:    "probe",
		StatusCode:     http.StatusForbidden,
		PayloadSnippet: "token=t146_probe",
	}
	if err := db.Create(&log).Error; err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}, WithDatabase(db))

	suggest := httptest.NewRecorder()
	server.Handler().ServeHTTP(suggest, httptest.NewRequest(http.MethodGet, "/api/attack-logs/1/whitelist-suggestions", nil))
	if suggest.Code != http.StatusOK {
		t.Fatalf("suggest status=%d body=%s", suggest.Code, suggest.Body.String())
	}
	if body := suggest.Body.String(); !strings.Contains(body, `"scope":"path"`) || !strings.Contains(body, `"siteId":"11"`) || !strings.Contains(body, `"path":"/pay/callback"`) || !strings.Contains(body, `"expiresAt"`) {
		t.Fatalf("suggestions are not minimal/auditable: %s", body)
	}

	apply := httptest.NewRecorder()
	server.Handler().ServeHTTP(apply, httptest.NewRequest(http.MethodPost, "/api/attack-logs/1/whitelist", strings.NewReader(`{"type":"param_whitelist","description":"t146 false positive"}`)))
	if apply.Code != http.StatusCreated {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	var response accessRule
	if err := json.Unmarshal(apply.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var rule database.AccessRule
	if err := db.First(&rule).Error; err != nil {
		t.Fatal(err)
	}
	if rule.Type != database.AccessRuleParamWhitelist || rule.Scope != "path" || rule.Value != "/pay/callback|token=t146_probe" || rule.SiteID != 11 || rule.CreatedFrom != "attack-log:1" {
		t.Fatalf("unexpected whitelist rule: %#v response=%#v", rule, response)
	}

	validate := httptest.NewRecorder()
	server.Handler().ServeHTTP(validate, httptest.NewRequest(http.MethodPost, "/api/attack-logs/1/whitelist-validate", nil))
	if validate.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", validate.Code, validate.Body.String())
	}
	if body := validate.Body.String(); !strings.Contains(body, `"afterDecision":"skip_detection"`) || !strings.Contains(body, `"equivalentStatus":"would_allow"`) {
		t.Fatalf("validation did not replay whitelist effect: %s", body)
	}

	var audits []database.AuditEvent
	if err := db.Find(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 || audits[0].Resource != "access-rule:1" || !strings.Contains(audits[0].Detail, "from attack log 1") {
		t.Fatalf("audit linkage missing: %#v", audits)
	}
}

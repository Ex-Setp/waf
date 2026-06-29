package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/accesscontrol"
	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/pipeline"
)

func TestT122AttackLogCanGenerateWhitelistAndAuditEvent(t *testing.T) {
	db := testDB(t)
	log := database.AttackLog{
		SiteID:         7,
		SiteName:       "业务站点",
		SourceIP:       "198.51.100.9",
		Method:         http.MethodGet,
		Path:           "/search?q=%3Cscript%3E",
		AttackType:     "XSS",
		Severity:       "high",
		Action:         "block",
		Stage:          "detection",
		RuleID:         "941100",
		RuleMessage:    "xss payload",
		StatusCode:     http.StatusForbidden,
		PayloadSnippet: "q=<script>",
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
	if body := suggest.Body.String(); !strings.Contains(body, "url_whitelist") || !strings.Contains(body, "param_whitelist") || !strings.Contains(body, "ip_whitelist") || !strings.Contains(body, "rule_disable") {
		t.Fatalf("missing whitelist suggestions: %s", body)
	}

	apply := httptest.NewRecorder()
	payload := `{"type":"param_whitelist","value":"q=<script>","description":"搜索参数误报"}`
	server.Handler().ServeHTTP(apply, httptest.NewRequest(http.MethodPost, "/api/attack-logs/1/whitelist", strings.NewReader(payload)))
	if apply.Code != http.StatusCreated {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	var rule accessRule
	if err := json.Unmarshal(apply.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.Type != database.AccessRuleParamWhitelist || rule.Value != "q=<script>" || rule.Status != "enabled" {
		t.Fatalf("unexpected rule: %#v", rule)
	}

	var audits []database.AuditEvent
	if err := db.Find(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 || audits[0].Type != "whitelist_created" || audits[0].SiteName != "业务站点" {
		t.Fatalf("audit event missing: %#v", audits)
	}

	result := accesscontrol.NewEvaluator([]database.AccessRule{{Type: database.AccessRuleParamWhitelist, Value: "q=<script>", Enabled: true}}).Evaluate(accesscontrol.Request{SiteID: 7, Path: "/search?q=%3Cscript%3E", Args: map[string][]string{"q": {"<script>"}}})
	if result.Decision != accesscontrol.DecisionSkipDetection {
		t.Fatalf("param whitelist decision=%s", result.Decision)
	}
}

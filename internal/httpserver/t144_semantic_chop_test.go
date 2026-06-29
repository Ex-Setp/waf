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

func TestT144SemanticHitsEnterAttackLogExplanationAndScoreBreakdown(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	semanticEngine := detection.NewSemanticEngine(nil, detection.SemanticOptions{})
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine), pipeline.WithSemantic(semanticEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096, EnableSemantic: true}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	site := database.Site{Name: "t144", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: true, SemanticProtection: true, PolicyMode: database.PolicyModeStandard, BlockScoreThreshold: 7}
	if err := site.SetDomains([]string{"t144.local"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	server.reloadRuntime(httptest.NewRequest(http.MethodGet, "/", nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E", nil)
	req.Host = "t144.local"
	req.RemoteAddr = "192.0.2.144:1001"
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	var log database.AttackLog
	if err := db.Order("created_at desc, id desc").First(&log).Error; err != nil {
		t.Fatalf("load attack log: %v", err)
	}
	if log.AttackType != "xss" || log.Stage != pipeline.StageSemantic || log.RuleID != "935003" {
		t.Fatalf("unexpected semantic attack log: %#v", log)
	}
	if !strings.Contains(log.ExplanationJSON, "semantic/xsschop") || !strings.Contains(log.ExplanationJSON, "url-decode") {
		t.Fatalf("semantic explanation missing evidence: %s", log.ExplanationJSON)
	}
	if !strings.Contains(log.ScoreBreakdown, `"id":935003`) || !strings.Contains(log.ScoreBreakdown, `"group":"xss"`) {
		t.Fatalf("semantic score breakdown missing rule: %s", log.ScoreBreakdown)
	}

	var explanation struct {
		SemanticDecision map[string]string `json:"semanticDecision"`
		MatchedRules     []struct {
			ID       int      `json:"id"`
			Source   string   `json:"source"`
			Group    string   `json:"group"`
			Evidence []string `json:"evidence"`
		} `json:"matchedRules"`
		ScoreBreakdown struct {
			Rules []struct {
				ID    int    `json:"id"`
				Group string `json:"group"`
				Score int    `json:"score"`
			} `json:"rules"`
		} `json:"scoreBreakdown"`
	}
	if err := json.Unmarshal([]byte(log.ExplanationJSON), &explanation); err != nil {
		t.Fatalf("parse explanation: %v\n%s", err, log.ExplanationJSON)
	}
	if explanation.SemanticDecision["status"] != "block" || !hasExplanationRule(explanation.MatchedRules, detection.SemanticXSSChopRuleID, "semantic/xsschop") {
		t.Fatalf("missing semantic decision/rule: %#v", explanation)
	}
	if !hasBreakdownRule(explanation.ScoreBreakdown.Rules, detection.SemanticXSSChopRuleID, "xss") {
		t.Fatalf("missing semantic breakdown in explanation: %#v", explanation.ScoreBreakdown.Rules)
	}
}

func hasExplanationRule(rules []struct {
	ID       int      `json:"id"`
	Source   string   `json:"source"`
	Group    string   `json:"group"`
	Evidence []string `json:"evidence"`
}, id int, source string) bool {
	for _, rule := range rules {
		if rule.ID == id && rule.Source == source {
			return true
		}
	}
	return false
}

func hasBreakdownRule(rules []struct {
	ID    int    `json:"id"`
	Group string `json:"group"`
	Score int    `json:"score"`
}, id int, group string) bool {
	for _, rule := range rules {
		if rule.ID == id && rule.Group == group {
			return true
		}
	}
	return false
}

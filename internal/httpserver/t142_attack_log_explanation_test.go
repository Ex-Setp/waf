package httpserver

import (
	"context"
	"encoding/csv"
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

type operatorSuggestionForTest struct {
	Type   string `json:"type"`
	Action string `json:"action"`
	Target string `json:"target"`
}

func TestT142AttackLogExplanationAndOperatorSuggestions(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer upstream.Close()

	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	createSite(t, server, "t142", "t142.local", upstream.URL, 5)
	createRule(t, server, `{"ruleId":142001,"name":"t142 xss","category":"custom","variable":"ARGS","operator":"@contains","pattern":"<script>alert(1)</script>","action":"deny","severity":"high","score":6,"source":"custom","enabled":true}`)

	assertWAFStatus(t, server, http.MethodGet, "/search?q=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E&password=secret-token", "t142.local", "192.0.2.142:1001", "", http.StatusForbidden, "encoded payload should block and create explained attack log")
	if err := server.audit.Stop(context.Background()); err != nil {
		t.Fatalf("stop audit: %v", err)
	}

	var log database.AttackLog
	if err := db.Order("created_at desc, id desc").First(&log).Error; err != nil {
		t.Fatalf("load attack log: %v", err)
	}
	if strings.TrimSpace(log.ExplanationJSON) == "" {
		t.Fatalf("expected explanation json")
	}
	if strings.TrimSpace(log.OperatorSuggestion) == "" {
		t.Fatalf("expected operator suggestions")
	}

	var explanation struct {
		SitePolicy struct {
			SiteName            string   `json:"siteName"`
			PolicyMode          string   `json:"policyMode"`
			BlockScoreThreshold int      `json:"blockScoreThreshold"`
			RuleGroups          []string `json:"ruleGroups"`
		} `json:"sitePolicy"`
		MatchedRules []struct {
			ID     int    `json:"id"`
			Group  string `json:"group"`
			Source string `json:"source"`
			Score  int    `json:"score"`
		} `json:"matchedRules"`
		RequestVariables []struct {
			Variable        string   `json:"variable"`
			RawValue        string   `json:"rawValue"`
			NormalizedValue string   `json:"normalizedValue"`
			DecodeSteps     []string `json:"decodeSteps"`
		} `json:"requestVariables"`
		NormalizationSteps []struct {
			Variable string   `json:"variable"`
			Steps    []string `json:"steps"`
		} `json:"normalizationSteps"`
		WhitelistDecision map[string]string `json:"whitelistDecision"`
		CCBotDecision     map[string]string `json:"ccBotDecision"`
		SemanticDecision  map[string]string `json:"semanticDecision"`
		FinalAction       string            `json:"finalAction"`
	}
	if err := json.Unmarshal([]byte(log.ExplanationJSON), &explanation); err != nil {
		t.Fatalf("parse explanation: %v\n%s", err, log.ExplanationJSON)
	}
	if explanation.SitePolicy.SiteName != "t142" || explanation.SitePolicy.BlockScoreThreshold != 5 {
		t.Fatalf("unexpected site policy explanation: %#v", explanation.SitePolicy)
	}
	if explanation.FinalAction != string(pipeline.DecisionBlock) {
		t.Fatalf("final action=%q", explanation.FinalAction)
	}
	if len(explanation.MatchedRules) == 0 || explanation.MatchedRules[0].ID != 142001 || explanation.MatchedRules[0].Group != "custom" {
		t.Fatalf("missing matched rule explanation: %#v", explanation.MatchedRules)
	}
	if len(explanation.RequestVariables) == 0 || len(explanation.NormalizationSteps) == 0 {
		t.Fatalf("expected request variables and normalization steps: %#v %#v", explanation.RequestVariables, explanation.NormalizationSteps)
	}
	if strings.Contains(log.ExplanationJSON, "secret-token") {
		t.Fatalf("explanation should be safe to redact before API/export: %s", log.ExplanationJSON)
	}

	var suggestions []operatorSuggestionForTest
	if err := json.Unmarshal([]byte(log.OperatorSuggestion), &suggestions); err != nil {
		t.Fatalf("parse suggestions: %v", err)
	}
	if !hasSuggestionAction(suggestions, "create_whitelist") || !hasSuggestionAction(suggestions, "open_site_policy") || !hasSuggestionAction(suggestions, "open_rule_group") {
		t.Fatalf("expected whitelist/site-policy/rule-group suggestions: %#v", suggestions)
	}

	list := httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/attack-logs?keyword=create_whitelist", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("attack logs status=%d body=%s", list.Code, list.Body.String())
	}
	var response attackLogResponse
	if err := json.Unmarshal(list.Body.Bytes(), &response); err != nil {
		t.Fatalf("parse attack logs response: %v", err)
	}
	if response.Total == 0 || response.Logs[0].ExplanationJSON == "" || response.Logs[0].OperatorSuggestion == "" {
		t.Fatalf("expected explanation and suggestion in API response: %#v", response)
	}
	if strings.Contains(response.Logs[0].ExplanationJSON, "secret-token") || strings.Contains(response.Logs[0].PayloadSnippet, "secret-token") {
		t.Fatalf("API response should redact sensitive values: %#v", response.Logs[0])
	}

	export := httptest.NewRecorder()
	server.Handler().ServeHTTP(export, httptest.NewRequest(http.MethodGet, "/api/attack-logs/export", nil))
	if export.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", export.Code, export.Body.String())
	}
	rows, err := csv.NewReader(strings.NewReader(export.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse csv export: %v", err)
	}
	if len(rows) < 2 || !containsString(rows[0], "explanation") || !containsString(rows[0], "operator_suggestion") {
		t.Fatalf("export should include explanation/suggestion columns: %#v", rows)
	}
	if strings.Contains(export.Body.String(), "secret-token") {
		t.Fatalf("export should redact sensitive values: %s", export.Body.String())
	}
}

func hasSuggestionAction(suggestions []operatorSuggestionForTest, action string) bool {
	for _, suggestion := range suggestions {
		if suggestion.Action == action {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

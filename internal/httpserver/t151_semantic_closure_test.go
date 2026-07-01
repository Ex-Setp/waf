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

func TestT151SemanticEvidencePersistsForExpandedCategories(t *testing.T) {
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
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 8192, EnableSemantic: true}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	site := database.Site{Name: "t151", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: true, SemanticProtection: true, PolicyMode: database.PolicyModeStrict, BlockScoreThreshold: 5}
	if err := site.SetDomains([]string{"t151.local"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	server.reloadRuntime(httptest.NewRequest(http.MethodGet, "/", nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("------test\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"avatar.jpg.php\"\r\nContent-Type: application/octet-stream\r\n\r\nbenign marker for upload test\r\n------test--"))
	req.Host = "t151.local"
	req.RemoteAddr = "192.0.2.151:1001"
	req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
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
	if log.AttackType != "upload" || log.Stage != pipeline.StageSemantic || log.RuleID != "935007" {
		t.Fatalf("unexpected semantic attack log: %#v", log)
	}
	if !strings.Contains(log.ExplanationJSON, "semantic/uploadchop") || !strings.Contains(log.ExplanationJSON, "structure:double_extension") {
		t.Fatalf("semantic explanation missing upload evidence: %s", log.ExplanationJSON)
	}
	if !strings.Contains(log.ScoreBreakdown, `"id":935007`) || !strings.Contains(log.ScoreBreakdown, `"group":"upload"`) {
		t.Fatalf("semantic score breakdown missing upload rule: %s", log.ScoreBreakdown)
	}

	var explanation struct {
		SemanticDecision map[string]string `json:"semanticDecision"`
		MatchedRules     []struct {
			ID       int      `json:"id"`
			Source   string   `json:"source"`
			Group    string   `json:"group"`
			Evidence []string `json:"evidence"`
		} `json:"matchedRules"`
	}
	if err := json.Unmarshal([]byte(log.ExplanationJSON), &explanation); err != nil {
		t.Fatalf("parse explanation: %v\n%s", err, log.ExplanationJSON)
	}
	if explanation.SemanticDecision["status"] != "block" || !hasExplanationRule(explanation.MatchedRules, detection.SemanticUploadRuleID, "semantic/uploadchop") {
		t.Fatalf("missing semantic upload decision/rule: %#v", explanation)
	}
}

func TestT151SemanticProtectionFalseDoesNotBlockExpandedSemanticHit(t *testing.T) {
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

	site := database.Site{Name: "t151-off", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: true, SemanticProtection: false, PolicyMode: database.PolicyModeStrict, BlockScoreThreshold: 5}
	if err := site.SetDomains([]string{"t151-off.local"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	server.reloadRuntime(httptest.NewRequest(http.MethodGet, "/", nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	req.Host = "t151-off.local"
	req.RemoteAddr = "192.0.2.151:1002"
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("semanticProtection=false status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
}

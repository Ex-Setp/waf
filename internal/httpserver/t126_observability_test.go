package httpserver

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestT126DashboardObservabilityAggregatesRealLogs(t *testing.T) {
	db := testDB(t)
	now := time.Now()
	access := []database.AccessLog{
		{SiteName: "app", SourceIP: "198.51.100.1", Method: http.MethodGet, Path: "/login", Status: 200, Decision: string(pipeline.DecisionAllow), LatencyMS: 10, CreatedAt: now.Add(-20 * time.Second).UnixMilli()},
		{SiteName: "app", SourceIP: "198.51.100.1", Method: http.MethodPost, Path: "/login", Status: 403, Decision: string(pipeline.DecisionBlock), LatencyMS: 20, CreatedAt: now.Add(-10 * time.Second).UnixMilli()},
		{SiteName: "app", SourceIP: "203.0.113.9", Method: http.MethodGet, Path: "/search", Status: 403, Decision: string(pipeline.DecisionBlock), LatencyMS: 30, CreatedAt: now.Add(-5 * time.Second).UnixMilli()},
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatal(err)
	}
	attacks := []database.AttackLog{
		{SiteName: "app", SourceIP: "198.51.100.1", Method: http.MethodPost, Path: "/login", AttackType: "SQLi", Severity: "critical", Action: "block", Stage: "detection", RuleID: "942100", RuleMessage: "sql injection", StatusCode: 403, PayloadSnippet: "username=admin&password=secret-token", CreatedAt: now.Add(-10 * time.Second).UnixMilli()},
		{SiteName: "app", SourceIP: "203.0.113.9", Method: http.MethodGet, Path: "/search", AttackType: "XSS", Severity: "high", Action: "block", Stage: "semantic", RuleID: "941100", RuleMessage: "xss", StatusCode: 403, PayloadSnippet: "q=<script>&token=abcdef", CreatedAt: now.Add(-5 * time.Second).UnixMilli()},
	}
	if err := db.Create(&attacks).Error; err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{}, WithDatabase(db))

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body dashboardOverview
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.QPS <= 0 || body.BlockRate <= 0.60 || len(body.TopIPs) == 0 || body.TopIPs[0].Value != "198.51.100.1" || body.TopIPs[0].Count != 2 {
		t.Fatalf("dashboard aggregate missing: %#v", body)
	}
	if len(body.TopPaths) == 0 || body.TopPaths[0].Value != "/login" || len(body.TopAttackTypes) == 0 || body.TopAttackTypes[0].Value == "" {
		t.Fatalf("dashboard top lists missing: %#v", body)
	}
}

func TestT126AttackLogExportAndAPIApplySensitiveMasking(t *testing.T) {
	db := testDB(t)
	log := database.AttackLog{SiteName: "app", SourceIP: "198.51.100.77", Method: http.MethodPost, Path: "/login?password=secret&token=abcdef&q=ok", AttackType: "SQLi", Severity: "critical", Action: "block", Stage: "detection", RuleID: "942100", RuleMessage: "matched password secret", StatusCode: 403, PayloadSnippet: "username=admin&password=secret&token=abcdef", CreatedAt: time.Now().UnixMilli()}
	if err := db.Create(&log).Error; err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{}, WithDatabase(db))

	apiRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(apiRec, httptest.NewRequest(http.MethodGet, "/api/attack-logs", nil))
	if strings.Contains(apiRec.Body.String(), "secret") || strings.Contains(apiRec.Body.String(), "abcdef") || !strings.Contains(apiRec.Body.String(), "[REDACTED]") {
		t.Fatalf("api response not masked: %s", apiRec.Body.String())
	}

	exportRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(exportRec, httptest.NewRequest(http.MethodGet, "/api/attack-logs/export", nil))
	rows, err := csv.NewReader(strings.NewReader(exportRec.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("export rows=%d body=%s", len(rows), exportRec.Body.String())
	}
	exported := strings.Join(rows[1], ",")
	if strings.Contains(exported, "secret") || strings.Contains(exported, "abcdef") || !strings.Contains(exported, "[REDACTED]") || !strings.Contains(exported, "942100") {
		t.Fatalf("export row not masked or missing details: %q", exported)
	}
}

func TestT126RuntimeAttackLogCapturesRawRequestDetails(t *testing.T) {
	db := testDB(t)
	processor := &processorStub{result: pipeline.Result{
		Decision:       pipeline.DecisionBlock,
		Reason:         "detection score 7 reached threshold 5",
		BlockedByStage: pipeline.StageDetection,
		Detection:      detection.Result{Decision: detection.DecisionBlock, Score: 7, Severity: "high", Matches: []detection.MatchedRule{{ID: 942100, Message: "SQL injection attempt", Group: "sqli", Action: detection.RuleActionDeny, Severity: "high", Score: 7}}},
	}}
	site := database.Site{ID: 1, Name: "app", Upstream: "http://127.0.0.1:65535", Status: database.SiteStatusEnabled, WAFEnabled: true, BlockScoreThreshold: 5}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 2048}, processor, WithDatabase(db))
	server.runtime = runtimeForTest(t, site)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login?password=secret&q=1", strings.NewReader("username=admin&password=secret&token=abcdef"))
	req.Host = "example.test"
	req.RemoteAddr = "198.51.100.77:4567"
	req.Header.Set("User-Agent", "curl/8.0")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := server.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	apiRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(apiRec, httptest.NewRequest(http.MethodGet, "/api/attack-logs", nil))
	body := apiRec.Body.String()
	for _, want := range []string{"942100", "SQL injection attempt", "detection", "block", "POST /login?password=", "Host: example.test", "User-Agent: curl/8.0"} {
		if !strings.Contains(body, want) {
			t.Fatalf("attack log response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "abcdef") || !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("raw request snippet not masked: %s", body)
	}
}

func TestT126RetentionEndpointDeletesExpiredLogs(t *testing.T) {
	db := testDB(t)
	old := time.Now().Add(-10 * 24 * time.Hour).UnixMilli()
	recent := time.Now().Add(-time.Hour).UnixMilli()
	if err := db.Create(&[]database.AccessLog{{Path: "/old", CreatedAt: old}, {Path: "/recent", CreatedAt: recent}}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&[]database.AttackLog{{Path: "/old", CreatedAt: old}, {Path: "/recent", CreatedAt: recent}}).Error; err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{}, WithDatabase(db))

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/logs/retention?days=7", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var accessCount int64
	var attackCount int64
	if err := db.Model(&database.AccessLog{}).Count(&accessCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&database.AttackLog{}).Count(&attackCount).Error; err != nil {
		t.Fatal(err)
	}
	if accessCount != 1 || attackCount != 1 {
		t.Fatalf("retention counts access=%d attack=%d", accessCount, attackCount)
	}
}

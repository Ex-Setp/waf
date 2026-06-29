package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/pipeline"
)

func TestT133ProtectionTrafficAggregatesFromRealLogs(t *testing.T) {
	db := testDB(t)
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, pipeline.New(pipeline.Config{}), WithDatabase(db))
	now := time.Now().UnixMilli()
	logs := []database.AccessLog{
		{RequestID: "allow-1", SiteID: 1, SiteName: "shop", Host: "shop.test", SourceIP: "10.0.0.1", Method: "GET", Path: "/", Status: 200, Decision: "allow", LatencyMS: 2, CreatedAt: now - 3000},
		{RequestID: "block-1", SiteID: 1, SiteName: "shop", Host: "shop.test", SourceIP: "10.0.0.2", Method: "GET", Path: "/login", Status: 403, Decision: "block", LatencyMS: 3, CreatedAt: now - 2000},
		{RequestID: "captcha-1", SiteID: 2, SiteName: "api", Host: "api.test", SourceIP: "10.0.0.2", Method: "POST", Path: "/api/pay", Status: 429, Decision: "captcha", LatencyMS: 5, CreatedAt: now - 1000},
		{RequestID: "observe-1", SiteID: 2, SiteName: "api", Host: "api.test", SourceIP: "10.0.0.3", Method: "GET", Path: "/api/pay", Status: 200, Decision: "observe", LatencyMS: 4, CreatedAt: now},
	}
	if err := db.Create(&logs).Error; err != nil {
		t.Fatalf("seed access logs: %v", err)
	}
	attacks := []database.AttackLog{
		{RequestID: "block-1", SiteID: 1, SiteName: "shop", SourceIP: "10.0.0.2", Method: "GET", Path: "/login", AttackType: "sqli", Severity: "critical", Action: "block", Stage: "detection", RuleID: "991001", StatusCode: 403, CreatedAt: now - 2000},
		{RequestID: "observe-1", SiteID: 2, SiteName: "api", SourceIP: "10.0.0.3", Method: "GET", Path: "/api/pay", AttackType: "xss", Severity: "medium", Action: "observe", Stage: "semantic", RuleID: "991002", StatusCode: 200, CreatedAt: now},
	}
	if err := db.Create(&attacks).Error; err != nil {
		t.Fatalf("seed attack logs: %v", err)
	}

	overview := getJSON[trafficOverviewResponse](t, server, "/api/protection/traffic/overview")
	if overview.TotalRequests != 4 || overview.BlockedRequests != 1 || overview.ObservedRequests != 1 || overview.CaptchaRequests != 1 || overview.BlockRate != 25 {
		t.Fatalf("unexpected overview: %#v", overview)
	}

	topIP := getJSON[trafficRankResponse](t, server, "/api/protection/traffic/top-ip")
	if len(topIP.Items) == 0 || topIP.Items[0].Key != "10.0.0.2" || topIP.Items[0].Count != 2 {
		t.Fatalf("unexpected top ip: %#v", topIP)
	}

	topPath := getJSON[trafficRankResponse](t, server, "/api/protection/traffic/top-path")
	if len(topPath.Items) == 0 || topPath.Items[0].Key != "/api/pay" || topPath.Items[0].Count != 2 {
		t.Fatalf("unexpected top path: %#v", topPath)
	}

	statusCodes := getJSON[trafficRankResponse](t, server, "/api/protection/traffic/status-codes")
	if len(statusCodes.Items) == 0 || !containsRank(statusCodes.Items, "403", 1) || !containsRank(statusCodes.Items, "200", 2) {
		t.Fatalf("unexpected status codes: %#v", statusCodes)
	}

	sites := getJSON[trafficRankResponse](t, server, "/api/protection/traffic/sites")
	if len(sites.Items) == 0 || !containsRank(sites.Items, "shop", 2) || !containsRank(sites.Items, "api", 2) {
		t.Fatalf("unexpected sites: %#v", sites)
	}

	trend := getJSON[trafficTrendResponse](t, server, "/api/protection/traffic/trend")
	if trend.Total == 0 || len(trend.Trend) == 0 {
		t.Fatalf("unexpected trend: %#v", trend)
	}

	filtered := getJSON[attackLogResponse](t, server, "/api/protection/attack-events?action=observe&attackType=xss")
	if filtered.Total != 1 || len(filtered.Logs) != 1 || filtered.Logs[0].AttackType != "xss" || filtered.Logs[0].Action != "observe" {
		t.Fatalf("unexpected filtered attack events: %#v", filtered)
	}

	pathDrill := getJSON[accessLogResponse](t, server, "/api/access-logs?path=/api/pay")
	if pathDrill.Total != 2 {
		t.Fatalf("expected path drilldown to return two access rows, got %#v", pathDrill)
	}
}

func TestT133ProtectionTrafficEmptyStateNoSamples(t *testing.T) {
	db := testDB(t)
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, pipeline.New(pipeline.Config{}), WithDatabase(db))
	overview := getJSON[trafficOverviewResponse](t, server, "/api/protection/traffic/overview")
	if overview.TotalRequests != 0 || overview.BlockedRequests != 0 || overview.QPS != 0 {
		t.Fatalf("empty overview should be zero, got %#v", overview)
	}
	top := getJSON[trafficRankResponse](t, server, "/api/protection/traffic/top-ip")
	if top.Total != 0 || len(top.Items) != 0 {
		t.Fatalf("empty top-ip should not contain samples, got %#v", top)
	}
	events := getJSON[attackLogResponse](t, server, "/api/protection/attack-events")
	if events.Total != 0 || len(events.Logs) != 0 || strings.Contains(toJSON(t, events), "203.0.113.24") {
		t.Fatalf("empty attack-events should not contain sample data, got %#v", events)
	}
}

func getJSON[T any](t *testing.T, server *Server, path string) T {
	t.Helper()
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%s", path, rec.Code, rec.Body.String())
	}
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v body=%s", path, err, rec.Body.String())
	}
	return out
}

func containsRank(items []trafficRankItem, key string, count int) bool {
	for _, item := range items {
		if item.Key == key && item.Count == count {
			return true
		}
	}
	return false
}

func toJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data)
}

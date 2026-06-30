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
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestT148RealLinkLogAndDashboardConsistency(t *testing.T) {
	db := testDB(t)
	ruleEngine, err := detection.NewManager("", nil, nil, false)
	if err != nil {
		t.Fatalf("new rule manager: %v", err)
	}
	if err := ruleEngine.UpsertRuntimeRule(detection.Rule{ID: 148001, Variable: "ARGS", Operator: "@contains", Pattern: "t148_rule_sqli", Action: detection.RuleActionDeny, Message: "t148 sql sample", Severity: "critical", Score: 8, Group: "sqli", Source: "test", Enabled: true}); err != nil {
		t.Fatalf("upsert sqli rule: %v", err)
	}
	if err := ruleEngine.UpsertRuntimeRule(detection.Rule{ID: 148002, Variable: "ARGS", Operator: "@contains", Pattern: "t148_rule_xss", Action: detection.RuleActionDeny, Message: "t148 xss sample", Severity: "high", Score: 8, Group: "xss", Source: "test", Enabled: true}); err != nil {
		t.Fatalf("upsert xss rule: %v", err)
	}
	semanticEngine := detection.NewSemanticEngine(nil, detection.SemanticOptions{})
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(ruleEngine), pipeline.WithSemantic(semanticEngine))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096, EnableSemantic: true}, processor, WithDatabase(db), WithDetectionEngine(ruleEngine))

	post := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"t148","domains":["t148.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"ccProtection":true,"semanticProtection":true,"policyMode":"custom","blockScoreThreshold":7,"ruleGroups":["sqli","xss","semantic"]}`, upstream.URL)
	server.Handler().ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(body)))
	if post.Code != http.StatusCreated {
		t.Fatalf("create site status=%d body=%s", post.Code, post.Body.String())
	}
	ccPolicy := httptest.NewRecorder()
	server.Handler().ServeHTTP(ccPolicy, httptest.NewRequest(http.MethodPost, "/api/cc-protection", strings.NewReader(`{"siteId":"1","name":"t148 cc","scope":"/cc*","threshold":1,"windowSeconds":60,"action":"block","enabled":true}`)))
	if ccPolicy.Code != http.StatusCreated {
		t.Fatalf("create cc status=%d body=%s", ccPolicy.Code, ccPolicy.Body.String())
	}

	assertT148Request(t, server, http.MethodGet, "/normal", "t148.local", "198.51.100.10:1001", "", http.StatusOK)
	assertT148Request(t, server, http.MethodGet, "/search?q=t148_rule_sqli", "t148.local", "198.51.100.11:1001", "", http.StatusForbidden)
	assertT148Request(t, server, http.MethodPost, "/comment", "t148.local", "198.51.100.12:1001", "body=t148_rule_xss", http.StatusForbidden)
	assertT148Request(t, server, http.MethodGet, "/semantic?q=union+select+name+from+users", "t148.local", "198.51.100.13:1001", "", http.StatusForbidden)
	assertT148Request(t, server, http.MethodGet, "/cc-sample", "t148.local", "198.51.100.14:1001", "", http.StatusOK)
	assertT148Request(t, server, http.MethodGet, "/cc-sample", "t148.local", "198.51.100.14:1002", "", http.StatusForbidden)

	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("stop server: %v", err)
	}

	access := getJSON[accessLogResponse](t, server, "/api/access-logs?site=t148&pageSize=100")
	attacks := getJSON[attackLogResponse](t, server, "/api/attack-logs?site=t148&pageSize=100")
	traffic := getJSON[trafficOverviewResponse](t, server, "/api/protection/traffic/overview?site=t148")
	dashboard := getJSON[dashboardOverview](t, server, "/api/dashboard/overview")
	if access.Total != 6 {
		t.Fatalf("access total=%d want 6: %#v", access.Total, access)
	}
	if attacks.Total < 4 {
		t.Fatalf("attack total=%d want >=4: %#v", attacks.Total, attacks)
	}
	if traffic.TotalRequests != access.Total || traffic.BlockedRequests < 4 {
		t.Fatalf("traffic not consistent: traffic=%#v access=%d", traffic, access.Total)
	}
	metrics := map[string]float64{}
	for _, metric := range dashboard.Metrics {
		metrics[metric.Key] = metric.Value
	}
	if int(metrics["requests"]) != access.Total || int(metrics["blocked"]) != attacks.Total {
		t.Fatalf("dashboard metrics not consistent: metrics=%#v access=%d attacks=%d", metrics, access.Total, attacks.Total)
	}
	for _, attackType := range []string{"sqli", "xss", "cc"} {
		filtered := getJSON[attackLogResponse](t, server, "/api/protection/attack-events?site=t148&attackType="+attackType)
		if filtered.Total == 0 {
			t.Fatalf("attackType %q filter returned no rows", attackType)
		}
	}
}

func assertT148Request(t *testing.T, server *Server, method, target, host, remoteAddr, body string, want int) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = host
	req.RemoteAddr = remoteAddr
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		var decoded map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
		t.Fatalf("%s %s status=%d want %d body=%s decoded=%#v", method, target, rec.Code, want, rec.Body.String(), decoded)
	}
}

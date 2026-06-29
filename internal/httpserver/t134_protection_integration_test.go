package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestT134ProtectionConfigIntegrationAcceptance(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin:" + r.URL.RequestURI()))
	}))
	defer upstream.Close()

	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	semanticEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("New semantic manager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine), pipeline.WithSemantic(semanticEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096, EnableSemantic: true}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	createSite := httptest.NewRecorder()
	server.Handler().ServeHTTP(createSite, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(fmt.Sprintf(`{"name":"t134","domains":["t134.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"policyMode":"standard","blockScoreThreshold":5,"ccProtection":true,"semanticProtection":true}`, upstream.URL))))
	if createSite.Code != http.StatusCreated {
		t.Fatalf("create site status=%d body=%s", createSite.Code, createSite.Body.String())
	}

	customRulePayload := `{"ruleId":134001,"name":"t134 custom deny","category":"custom","variable":"ARGS","operator":"@contains","pattern":"t134_probe","action":"deny","severity":"high","score":9,"source":"custom","enabled":true}`
	createRule := httptest.NewRecorder()
	server.Handler().ServeHTTP(createRule, httptest.NewRequest(http.MethodPost, "/api/protection/rules", strings.NewReader(customRulePayload)))
	if createRule.Code != http.StatusCreated {
		t.Fatalf("create protection rule status=%d body=%s", createRule.Code, createRule.Body.String())
	}
	assertWAFStatus(t, server, "GET", "/search?q=t134_probe", "t134.local", "192.0.2.134:1001", "", http.StatusForbidden, "custom rule should block attack request")

	disableRule := httptest.NewRecorder()
	server.Handler().ServeHTTP(disableRule, httptest.NewRequest(http.MethodPost, "/api/protection/rules/1/disable", nil))
	if disableRule.Code != http.StatusOK {
		t.Fatalf("disable rule status=%d body=%s", disableRule.Code, disableRule.Body.String())
	}
	assertWAFStatus(t, server, "GET", "/search?q=t134_probe", "t134.local", "192.0.2.134:1002", "", http.StatusOK, "disabled rule should allow same request")

	thresholdRulePayload := `{"ruleId":134002,"name":"t134 threshold rule","category":"custom","variable":"ARGS","operator":"@contains","pattern":"threshold_probe","action":"deny","severity":"medium","score":6,"source":"custom","enabled":true}`
	createThresholdRule := httptest.NewRecorder()
	server.Handler().ServeHTTP(createThresholdRule, httptest.NewRequest(http.MethodPost, "/api/protection/rules", strings.NewReader(thresholdRulePayload)))
	if createThresholdRule.Code != http.StatusCreated {
		t.Fatalf("create threshold rule status=%d body=%s", createThresholdRule.Code, createThresholdRule.Body.String())
	}
	looseSite := httptest.NewRecorder()
	server.Handler().ServeHTTP(looseSite, httptest.NewRequest(http.MethodPut, "/api/sites/1", strings.NewReader(fmt.Sprintf(`{"name":"t134","domains":["t134.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"policyMode":"custom","blockScoreThreshold":10,"ccProtection":true,"semanticProtection":true,"ruleGroups":["custom"]}`, upstream.URL))))
	if looseSite.Code != http.StatusOK {
		t.Fatalf("raise threshold status=%d body=%s", looseSite.Code, looseSite.Body.String())
	}
	assertWAFStatus(t, server, "GET", "/search?q=threshold_probe", "t134.local", "192.0.2.134:1003", "", http.StatusOK, "score below modified threshold should observe/allow")
	tightSite := httptest.NewRecorder()
	server.Handler().ServeHTTP(tightSite, httptest.NewRequest(http.MethodPut, "/api/sites/1", strings.NewReader(fmt.Sprintf(`{"name":"t134","domains":["t134.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"policyMode":"custom","blockScoreThreshold":5,"ccProtection":true,"semanticProtection":true,"ruleGroups":["custom"]}`, upstream.URL))))
	if tightSite.Code != http.StatusOK {
		t.Fatalf("lower threshold status=%d body=%s", tightSite.Code, tightSite.Body.String())
	}
	assertWAFStatus(t, server, "GET", "/search?q=threshold_probe", "t134.local", "192.0.2.134:1004", "", http.StatusForbidden, "score above modified threshold should block")

	whitelist := httptest.NewRecorder()
	server.Handler().ServeHTTP(whitelist, httptest.NewRequest(http.MethodPost, "/api/access-rules", strings.NewReader(`{"type":"param_whitelist","value":"q=threshold_probe","description":"t134 false positive","status":"enabled"}`)))
	if whitelist.Code != http.StatusCreated {
		t.Fatalf("create whitelist status=%d body=%s", whitelist.Code, whitelist.Body.String())
	}
	assertWAFStatus(t, server, "GET", "/search?q=threshold_probe", "t134.local", "192.0.2.134:1005", "", http.StatusOK, "param whitelist should skip corresponding detection")

	ccPolicy := httptest.NewRecorder()
	server.Handler().ServeHTTP(ccPolicy, httptest.NewRequest(http.MethodPost, "/api/cc-protection", strings.NewReader(`{"name":"t134 cc block","scope":"/cc","threshold":1,"windowSeconds":60,"action":"block","enabled":true}`)))
	if ccPolicy.Code != http.StatusCreated {
		t.Fatalf("create cc policy status=%d body=%s", ccPolicy.Code, ccPolicy.Body.String())
	}
	assertWAFStatus(t, server, "GET", "/cc", "t134.local", "198.51.100.134:2001", "", http.StatusOK, "first cc request should pass")
	assertWAFStatus(t, server, "GET", "/cc", "t134.local", "198.51.100.134:2002", "", http.StatusForbidden, "second cc request should block")

	semanticPayload := "select credit_card from users union select password from vault"
	fp := database.SemanticFingerprint{Hash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Language: "sql", Skeleton: "(select union)", SamplePayload: semanticPayload, Action: "log", Status: database.SemanticFingerprintStatusObserving, Hits: 6, Source: "semantic-detection", SiteID: 1, SiteName: "t134"}
	if err := db.Create(&fp).Error; err != nil {
		t.Fatalf("seed semantic fingerprint: %v", err)
	}
	semanticSite := httptest.NewRecorder()
	server.Handler().ServeHTTP(semanticSite, httptest.NewRequest(http.MethodPut, "/api/sites/1", strings.NewReader(fmt.Sprintf(`{"name":"t134","domains":["t134.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"policyMode":"standard","blockScoreThreshold":5,"ccProtection":true,"semanticProtection":true,"ruleGroups":["custom","semantic"]}`, upstream.URL))))
	if semanticSite.Code != http.StatusOK {
		t.Fatalf("enable semantic rule group status=%d body=%s", semanticSite.Code, semanticSite.Body.String())
	}
	promote := httptest.NewRecorder()
	server.Handler().ServeHTTP(promote, httptest.NewRequest(http.MethodPost, "/api/semantic-fingerprints/1/promote-rule", nil))
	if promote.Code != http.StatusOK {
		t.Fatalf("promote semantic rule status=%d body=%s", promote.Code, promote.Body.String())
	}
	assertWAFStatus(t, server, "GET", "/semantic?q="+url.QueryEscape(semanticPayload), "t134.local", "203.0.113.134:3001", "", http.StatusForbidden, "promoted semantic fingerprint should block similar payload")
	rollback := httptest.NewRecorder()
	server.Handler().ServeHTTP(rollback, httptest.NewRequest(http.MethodPost, "/api/semantic-fingerprints/1/rollback", nil))
	if rollback.Code != http.StatusOK {
		t.Fatalf("rollback semantic rule status=%d body=%s", rollback.Code, rollback.Body.String())
	}
	assertWAFStatus(t, server, "GET", "/semantic?q="+url.QueryEscape(semanticPayload), "t134.local", "203.0.113.134:3002", "", http.StatusOK, "rolled back semantic fingerprint should no longer block")

	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	var accessCount, attackCount int64
	if err := db.Model(&database.AccessLog{}).Where("site_name = ?", "t134").Count(&accessCount).Error; err != nil {
		t.Fatalf("count access logs: %v", err)
	}
	if err := db.Model(&database.AttackLog{}).Where("site_name = ?", "t134").Count(&attackCount).Error; err != nil {
		t.Fatalf("count attack logs: %v", err)
	}
	if accessCount < 9 || attackCount < 4 {
		t.Fatalf("expected runtime traffic reflected in logs, access=%d attack=%d", accessCount, attackCount)
	}

	attackEvents := getJSON[attackLogResponse](t, server, "/api/protection/attack-events?site=t134&page=1&pageSize=50")
	if attackEvents.Total < 4 || !containsAttackStage(attackEvents.Logs, "detection") || !containsAttackStage(attackEvents.Logs, "cc") {
		t.Fatalf("attack events do not explain detection/cc decisions: %#v", attackEvents)
	}
	overview := getJSON[trafficOverviewResponse](t, server, "/api/protection/traffic/overview?site=t134")
	if overview.TotalRequests < int(accessCount) || overview.BlockedRequests < 4 {
		t.Fatalf("traffic overview did not reflect integration requests: %#v access=%d", overview, accessCount)
	}
	var audits []database.AuditEvent
	if err := db.Where("type IN ?", []string{"protection_rule", "whitelist_hit", "whitelist_created"}).Find(&audits).Error; err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	if len(audits) == 0 {
		t.Fatalf("expected protection/whitelist audit events")
	}
}

func assertWAFStatus(t *testing.T, server *Server, method, path, host, remoteAddr, body string, want int, reason string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = host
	req.RemoteAddr = remoteAddr
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s: status=%d want=%d body=%s", reason, rec.Code, want, rec.Body.String())
	}
}

func containsAttackStage(events []attackLogEntry, stage string) bool {
	for _, event := range events {
		if event.Stage == stage {
			return true
		}
	}
	return false
}

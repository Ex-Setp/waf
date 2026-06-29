package httpserver

import (
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

func TestT139FalsePositiveWhitelistAndRuleExclusion(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer upstream.Close()

	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	createSite(t, server, "t139a", "t139a.local", upstream.URL, 5)
	createSite(t, server, "t139b", "t139b.local", upstream.URL, 5)
	createRule(t, server, `{"ruleId":139001,"name":"t139 custom","category":"custom","variable":"ARGS","operator":"@contains","pattern":"t139_probe","action":"deny","severity":"medium","score":6,"source":"custom","enabled":true}`)

	assertWAFStatus(t, server, http.MethodGet, "/pay?memo=t139_probe", "t139a.local", "192.0.2.201:1001", "", http.StatusForbidden, "baseline should block before whitelist")
	assertWAFStatus(t, server, http.MethodGet, "/pay?memo=t139_probe", "t139b.local", "192.0.2.202:1001", "", http.StatusForbidden, "other site should block before whitelist")

	createWhitelist := httptest.NewRecorder()
	server.Handler().ServeHTTP(createWhitelist, httptest.NewRequest(http.MethodPost, "/api/protection/whitelists", strings.NewReader(`{"siteId":"1","type":"url_whitelist","value":"/pay","scope":"path","description":"t139 false positive","status":"enabled"}`)))
	if createWhitelist.Code != http.StatusCreated {
		t.Fatalf("create whitelist status=%d body=%s", createWhitelist.Code, createWhitelist.Body.String())
	}
	assertWAFStatus(t, server, http.MethodGet, "/pay?memo=t139_probe", "t139a.local", "192.0.2.201:1002", "", http.StatusOK, "site/path whitelist should allow false positive")
	assertWAFStatus(t, server, http.MethodGet, "/admin?memo=t139_probe", "t139a.local", "192.0.2.201:1003", "", http.StatusForbidden, "path scoped whitelist must not affect other paths")
	assertWAFStatus(t, server, http.MethodGet, "/pay?memo=t139_probe", "t139b.local", "192.0.2.202:1002", "", http.StatusForbidden, "site scoped whitelist must not affect other sites")

	createExpired := httptest.NewRecorder()
	server.Handler().ServeHTTP(createExpired, httptest.NewRequest(http.MethodPost, "/api/protection/whitelists", strings.NewReader(`{"siteId":"1","type":"url_whitelist","value":"/expired","scope":"path","description":"expired","expiresAt":"`+time.Now().Add(-time.Hour).Format(time.RFC3339)+`","status":"enabled"}`)))
	if createExpired.Code != http.StatusCreated {
		t.Fatalf("create expired whitelist status=%d body=%s", createExpired.Code, createExpired.Body.String())
	}
	assertWAFStatus(t, server, http.MethodGet, "/expired?memo=t139_probe", "t139a.local", "192.0.2.201:1004", "", http.StatusForbidden, "expired whitelist must not apply")

	createExclusion := httptest.NewRecorder()
	server.Handler().ServeHTTP(createExclusion, httptest.NewRequest(http.MethodPost, "/api/protection/whitelists", strings.NewReader(`{"siteId":"1","type":"rule_disable","value":"139001","ruleId":"139001","scope":"site","variable":"ARGS:memo","description":"t139 rule exclusion","status":"enabled"}`)))
	if createExclusion.Code != http.StatusCreated {
		t.Fatalf("create rule exclusion status=%d body=%s", createExclusion.Code, createExclusion.Body.String())
	}
	assertWAFStatus(t, server, http.MethodGet, "/other?memo=t139_probe", "t139a.local", "192.0.2.201:1005", "", http.StatusOK, "rule exclusion should disable matched rule before scoring")

	var auditCount int64
	if err := db.Model(&database.AuditEvent{}).Where("type IN ?", []string{"whitelist_created", "whitelist_hit"}).Count(&auditCount).Error; err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditCount < 2 {
		t.Fatalf("expected whitelist create/hit audit events, got %d", auditCount)
	}
}

package httpserver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestT138SitePolicyPublishVersionRollback(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin:" + r.URL.RequestURI()))
	}))
	defer upstream.Close()

	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	createSite(t, server, "t138a", "t138a.local", upstream.URL, 10)
	createSite(t, server, "t138b", "t138b.local", upstream.URL, 5)
	createRule(t, server, `{"ruleId":138001,"name":"t138 custom","category":"custom","variable":"ARGS","operator":"@contains","pattern":"t138_probe","action":"deny","severity":"medium","score":6,"source":"custom","enabled":true}`)

	assertWAFStatus(t, server, http.MethodGet, "/search?q=t138_probe", "t138a.local", "192.0.2.138:1001", "", http.StatusOK, "site A high threshold should observe/allow")
	assertWAFStatus(t, server, http.MethodGet, "/search?q=t138_probe", "t138b.local", "192.0.2.139:1001", "", http.StatusForbidden, "site B low threshold should block")

	strictDraft := httptest.NewRecorder()
	server.Handler().ServeHTTP(strictDraft, httptest.NewRequest(http.MethodPut, "/api/protection/site-policies/1", strings.NewReader(`{"mode":"strict","enabledRuleGroups":["custom"],"crsParanoiaLevel":1,"inboundThreshold":5,"outboundThreshold":5,"defaultAction":"block"}`)))
	if strictDraft.Code != http.StatusOK {
		t.Fatalf("draft strict policy status=%d body=%s", strictDraft.Code, strictDraft.Body.String())
	}
	publishStrict := httptest.NewRecorder()
	server.Handler().ServeHTTP(publishStrict, httptest.NewRequest(http.MethodPost, "/api/protection/site-policies/1/publish", nil))
	if publishStrict.Code != http.StatusOK {
		t.Fatalf("publish strict status=%d body=%s", publishStrict.Code, publishStrict.Body.String())
	}
	strictPolicy := getJSON[siteProtectionPolicy](t, server, "/api/protection/site-policies/1")
	strictVersion := strictPolicy.RuntimeVersion
	if strictPolicy.Mode != database.PolicyModeStrict || strictPolicy.InboundThreshold != 5 || strictVersion == "" {
		t.Fatalf("unexpected strict policy: %#v", strictPolicy)
	}
	assertWAFStatus(t, server, http.MethodGet, "/search?q=t138_probe", "t138a.local", "192.0.2.138:1002", "", http.StatusForbidden, "published strict policy should hot reload and block")

	looseDraft := httptest.NewRecorder()
	server.Handler().ServeHTTP(looseDraft, httptest.NewRequest(http.MethodPut, "/api/protection/site-policies/1", strings.NewReader(`{"mode":"loose","enabledRuleGroups":["custom"],"crsParanoiaLevel":1,"inboundThreshold":10,"outboundThreshold":10,"defaultAction":"block"}`)))
	if looseDraft.Code != http.StatusOK {
		t.Fatalf("draft loose policy status=%d body=%s", looseDraft.Code, looseDraft.Body.String())
	}
	publishLoose := httptest.NewRecorder()
	server.Handler().ServeHTTP(publishLoose, httptest.NewRequest(http.MethodPost, "/api/protection/site-policies/1/publish", nil))
	if publishLoose.Code != http.StatusOK {
		t.Fatalf("publish loose status=%d body=%s", publishLoose.Code, publishLoose.Body.String())
	}
	assertWAFStatus(t, server, http.MethodGet, "/search?q=t138_probe", "t138a.local", "192.0.2.138:1003", "", http.StatusOK, "published loose policy should allow below threshold")

	versions := getJSON[map[string]any](t, server, "/api/protection/site-policies/1/versions")
	if total, _ := versions["total"].(float64); total < 2 {
		t.Fatalf("expected at least 2 policy versions, got %#v", versions)
	}

	rollback := httptest.NewRecorder()
	server.Handler().ServeHTTP(rollback, httptest.NewRequest(http.MethodPost, "/api/protection/site-policies/1/rollback?version="+strictVersion, nil))
	if rollback.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollback.Code, rollback.Body.String())
	}
	assertWAFStatus(t, server, http.MethodGet, "/search?q=t138_probe", "t138a.local", "192.0.2.138:1004", "", http.StatusForbidden, "rollback should restore strict blocking behavior")

	var policyCount, versionCount, auditCount int64
	if err := db.Model(&database.SiteProtectionPolicy{}).Where("site_id = ?", 1).Count(&policyCount).Error; err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if err := db.Model(&database.PolicyVersion{}).Where("site_id = ?", 1).Count(&versionCount).Error; err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if err := db.Model(&database.PolicyAudit{}).Where("site_id = ?", 1).Count(&auditCount).Error; err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if policyCount != 1 || versionCount < 2 || auditCount < 3 {
		t.Fatalf("expected policy/version/audit persistence, policy=%d version=%d audit=%d", policyCount, versionCount, auditCount)
	}
}

func createSite(t *testing.T, server *Server, name, host, upstream string, threshold int) {
	t.Helper()
	rec := httptest.NewRecorder()
	policyMode := database.PolicyModeStandard
	if threshold > 0 && threshold < 7 {
		policyMode = database.PolicyModeCustom
	}
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(fmt.Sprintf(`{"name":%q,"domains":[%q],"upstream":%q,"status":"enabled","wafEnabled":true,"policyMode":%q,"blockScoreThreshold":%d,"semanticProtection":true,"ruleGroups":["custom"]}`, name, host, upstream, policyMode, threshold))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create site %s status=%d body=%s", name, rec.Code, rec.Body.String())
	}
}

func createRule(t *testing.T, server *Server, payload string) {
	t.Helper()
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/protection/rules", strings.NewReader(payload)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create rule status=%d body=%s", rec.Code, rec.Body.String())
	}
}

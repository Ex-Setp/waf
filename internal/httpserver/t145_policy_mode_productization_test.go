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

func TestT145PolicyModeProductization(t *testing.T) {
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

	createPolicyModeSite(t, server, "t145-observe", "t145-observe.local", upstream.URL, "observe", 3)
	observe := getJSON[protectedSite](t, server, "/api/sites/1")
	if observe.PolicyMode != database.PolicyModeObserve || observe.BlockScoreThreshold != 100 || observe.CCProtection || observe.SemanticProtection {
		t.Fatalf("observe defaults not productized: %#v", observe)
	}

	createPolicyModeSite(t, server, "t145-strict", "t145-strict.local", upstream.URL, "strict", 30)
	strict := getJSON[protectedSite](t, server, "/api/sites/2")
	if strict.PolicyMode != database.PolicyModeStrict || strict.BlockScoreThreshold != 5 || !strict.CCProtection || !strict.SemanticProtection {
		t.Fatalf("strict defaults not productized: %#v", strict)
	}

	createPolicyModeSite(t, server, "t145-custom", "t145-custom.local", upstream.URL, "custom", 4)
	custom := getJSON[protectedSite](t, server, "/api/sites/3")
	if custom.PolicyMode != database.PolicyModeCustom || custom.BlockScoreThreshold != 4 {
		t.Fatalf("custom threshold not preserved: %#v", custom)
	}

	createRule(t, server, `{"ruleId":145001,"name":"t145 mode rule","category":"custom","variable":"ARGS","operator":"@contains","pattern":"t145_probe","action":"deny","severity":"medium","score":6,"source":"custom","enabled":true}`)
	assertWAFStatus(t, server, http.MethodGet, "/search?q=t145_probe", "t145-observe.local", "192.0.2.145:1001", "", http.StatusOK, "observe mode should use high threshold")
	assertWAFStatus(t, server, http.MethodGet, "/search?q=t145_probe", "t145-strict.local", "192.0.2.145:1002", "", http.StatusForbidden, "strict mode should hot runtime block")
	assertWAFStatus(t, server, http.MethodGet, "/search?q=t145_probe", "t145-custom.local", "192.0.2.145:1003", "", http.StatusForbidden, "custom threshold should hot runtime block")

	updateCustom := httptest.NewRecorder()
	server.Handler().ServeHTTP(updateCustom, httptest.NewRequest(http.MethodPut, "/api/sites/3", strings.NewReader(fmt.Sprintf(`{"name":"t145-custom","domains":["t145-custom.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"policyMode":"standard","blockScoreThreshold":4,"ruleGroups":["custom"]}`, upstream.URL))))
	if updateCustom.Code != http.StatusOK {
		t.Fatalf("update custom to standard status=%d body=%s", updateCustom.Code, updateCustom.Body.String())
	}
	standard := getJSON[protectedSite](t, server, "/api/sites/3")
	if standard.PolicyMode != database.PolicyModeStandard || standard.BlockScoreThreshold != 7 {
		t.Fatalf("standard mode should reset to default threshold: %#v", standard)
	}
	assertWAFStatus(t, server, http.MethodGet, "/search?q=t145_probe", "t145-custom.local", "192.0.2.145:1004", "", http.StatusOK, "standard mode should observe below default threshold")
}

func createPolicyModeSite(t *testing.T, server *Server, name, host, upstream, mode string, threshold int) {
	t.Helper()
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(fmt.Sprintf(`{"name":%q,"domains":[%q],"upstream":%q,"status":"enabled","wafEnabled":true,"policyMode":%q,"blockScoreThreshold":%d,"ruleGroups":["custom"]}`, name, host, upstream, mode, threshold))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create site %s status=%d body=%s", name, rec.Code, rec.Body.String())
	}
}

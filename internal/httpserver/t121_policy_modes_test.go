package httpserver

import (
	"context"
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

func TestT121DefaultProtectionPolicyModes(t *testing.T) {
	cases := []struct {
		name       string
		mode       string
		path       string
		wantStatus int
		wantCC     bool
		wantSem    bool
		wantThresh int
	}{
		{name: "loose observes high risk by high threshold", mode: database.PolicyModeLoose, path: "/search?q=1+union+select+password", wantStatus: http.StatusOK, wantCC: false, wantSem: false, wantThresh: 100},
		{name: "standard blocks high risk", mode: database.PolicyModeStandard, path: "/search?q=1+union+select+password", wantStatus: http.StatusForbidden, wantCC: false, wantSem: true, wantThresh: 7},
		{name: "strict blocks and enables cc semantic", mode: database.PolicyModeStrict, path: "/json-api/order?q=1+union+select+password", wantStatus: http.StatusForbidden, wantCC: true, wantSem: true, wantThresh: 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := testDB(t)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
			defer upstream.Close()
			rules, err := detection.NewManager("../../rules", nil, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024, EnableSemantic: true}, pipeline.New(pipeline.Config{}, pipeline.WithDetection(rules)), WithDatabase(db))

			create := httptest.NewRecorder()
			body := fmt.Sprintf(`{"name":%q,"domains":[%q],"upstream":%q,"status":"enabled","wafEnabled":true,"policyMode":%q}`, tc.mode, tc.mode+".local", upstream.URL, tc.mode)
			server.Handler().ServeHTTP(create, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(body)))
			if create.Code != http.StatusCreated {
				t.Fatalf("create site=%d %s", create.Code, create.Body.String())
			}

			runtimeSite, ok := server.runtime.MatchSite(tc.mode + ".local")
			if !ok {
				t.Fatal("site runtime missing")
			}
			if runtimeSite.CCProtection != tc.wantCC || runtimeSite.SemanticProtection != tc.wantSem || runtimeSite.BlockScoreThreshold != tc.wantThresh {
				t.Fatalf("runtime policy cc=%v sem=%v threshold=%d", runtimeSite.CCProtection, runtimeSite.SemanticProtection, runtimeSite.BlockScoreThreshold)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Host = tc.mode + ".local"
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if err := server.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

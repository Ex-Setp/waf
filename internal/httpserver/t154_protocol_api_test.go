package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/crs"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestT154ProtocolAPISecurityClosure(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	manager := crs.NewManager(crs.Config{
		Enabled:           true,
		RulesDir:          projectRootForTest(t) + "\\rules",
		ParanoiaLevel:     1,
		InboundThreshold:  5,
		OutboundThreshold: 5,
		RequestBodyLimit:  10 * 1024 * 1024,
	})
	engine, err := detection.NewCorazaEngine(manager)
	if err != nil {
		t.Fatalf("NewCorazaEngine: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(engine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 1024 * 1024}, processor, WithDatabase(db))

	createSite(t, server, "t154", "t154.local", upstream.URL, 5)
	siteUpdate := httptest.NewRecorder()
	siteBody := `{"name":"t154","domains":["t154.local"],"upstream":"` + upstream.URL + `","status":"enabled","wafEnabled":true,"policyMode":"custom","blockScoreThreshold":5,"semanticProtection":true,"ruleGroups":["protocol","api","xxe"]}`
	server.Handler().ServeHTTP(siteUpdate, httptest.NewRequest(http.MethodPut, "/api/sites/1", strings.NewReader(siteBody)))
	if siteUpdate.Code != http.StatusOK {
		t.Fatalf("update site groups status=%d body=%s", siteUpdate.Code, siteUpdate.Body.String())
	}

	tests := []struct {
		name          string
		method        string
		target        string
		headers       map[string][]string
		body          string
		wantStatus    int
		wantRuleID    string
		wantEvidence  []string
		wantReasonSub string
	}{
		{
			name:       "graphql introspection blocks",
			method:     http.MethodPost,
			target:     "/gql",
			headers:    map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {"Mozilla/5.0"}},
			body:       `{"query":"{viewer:__schema{types{name}}}"}`,
			wantStatus: http.StatusForbidden,
			wantRuleID: "910001",
			wantEvidence: []string{
				"ARGS:graphql.has_introspection=true",
				"ARGS:graphql.has_alias_introspection=true",
				"JSON:query",
			},
		},
		{
			name:       "graphql depth abuse blocks",
			method:     http.MethodPost,
			target:     "/gql",
			headers:    map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {"Mozilla/5.0"}},
			body:       `{"query":"{a{b{c{d{e{f{g{h{i{j{k{l{m}}}}}}}}}}}}"}`,
			wantStatus: http.StatusForbidden,
			wantRuleID: "910008",
			wantEvidence: []string{
				"ARGS:graphql.depth=13",
			},
		},
		{
			name:       "jwt none blocks",
			method:     http.MethodGet,
			target:     "/account/me",
			headers:    map[string][]string{"Authorization": {"Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."}, "User-Agent": {"Mozilla/5.0"}},
			wantStatus: http.StatusForbidden,
			wantRuleID: "910030",
			wantEvidence: []string{
				"ARGS:jwt.header.alg=none",
				"ARGS:jwt.signature.present=false",
			},
		},
		{
			name:       "jwt role tamper blocks on json path",
			method:     http.MethodPost,
			target:     "/account/admin",
			headers:    map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {"Mozilla/5.0"}},
			body:       `{"role":"admin"}`,
			wantStatus: http.StatusForbidden,
			wantRuleID: "910034",
			wantEvidence: []string{
				"ARGS:json.role=admin",
			},
		},
		{
			name:       "json prototype pollution blocks",
			method:     http.MethodPost,
			target:     "/settings/profile",
			headers:    map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {"Mozilla/5.0"}},
			body:       `{"__proto__":{"admin":true}}`,
			wantStatus: http.StatusForbidden,
			wantRuleID: "910021",
			wantEvidence: []string{
				"JSON:__proto__",
			},
		},
		{
			name:       "xxe blocks",
			method:     http.MethodPost,
			target:     "/xml/upload",
			headers:    map[string][]string{"Content-Type": {"application/xml"}, "User-Agent": {"Mozilla/5.0"}},
			body:       `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
			wantStatus: http.StatusForbidden,
			wantRuleID: "906001",
			wantEvidence: []string{
				"REQUEST_BODY=<?xml version=\"1.0\"?><!DOCTYPE root",
			},
		},
		{
			name:       "duplicate content-length blocks",
			method:     http.MethodPost,
			target:     "/orders/create",
			headers:    map[string][]string{"Content-Type": {"application/json"}, "Content-Length": {"10", "10"}, "User-Agent": {"Mozilla/5.0"}},
			body:       `{"ok":1}`,
			wantStatus: http.StatusForbidden,
			wantRuleID: "909048",
			wantEvidence: []string{
				"ARGS:request.content_length.count=2",
			},
		},
		{
			name:       "transfer encoding confusion blocks",
			method:     http.MethodPost,
			target:     "/orders/create",
			headers:    map[string][]string{"Transfer-Encoding": {"chunked"}, "Content-Length": {"50"}, "User-Agent": {"Mozilla/5.0"}},
			body:       "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
			wantStatus: http.StatusForbidden,
			wantRuleID: "909002",
			wantEvidence: []string{
				"REQUEST_HEADERS:Transfer-Encoding=chunked",
				"REQUEST_HEADERS:Content-Length=50",
			},
		},
		{
			name:       "invalid method blocks",
			method:     "FOOBAR",
			target:     "/",
			headers:    map[string][]string{"User-Agent": {"Mozilla/5.0"}},
			wantStatus: http.StatusForbidden,
			wantRuleID: "909023",
			wantEvidence: []string{
				"REQUEST_METHOD=FOOBAR",
			},
		},
		{
			name:       "benign json api allowed",
			method:     http.MethodPost,
			target:     "/profile/update",
			headers:    map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {"Mozilla/5.0"}},
			body:       `{"profile":{"bio":"hello world"},"page":1}`,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			req.Host = "t154.local"
			req.RemoteAddr = "192.0.2.154:1001"
			for key, values := range tc.headers {
				req.Header[key] = append([]string(nil), values...)
			}
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			flushAudit(t, server)

			if tc.wantStatus == http.StatusOK {
				return
			}

			var log database.AttackLog
			if err := db.Order("created_at desc, id desc").First(&log).Error; err != nil {
				t.Fatalf("load attack log: %v", err)
			}
			if strings.TrimSpace(log.ExplanationJSON) == "" {
				t.Fatalf("expected explanation json")
			}
			var explanation struct {
				MatchedRules []struct {
					ID       int      `json:"id"`
					Evidence []string `json:"evidence"`
				} `json:"matchedRules"`
				RequestVariables []struct {
					Variable string `json:"variable"`
				} `json:"requestVariables"`
			}
			if err := json.Unmarshal([]byte(log.ExplanationJSON), &explanation); err != nil {
				t.Fatalf("parse explanation: %v\n%s", err, log.ExplanationJSON)
			}
			if len(explanation.MatchedRules) == 0 {
				t.Fatalf("expected matched rules in explanation")
			}
			if !hasMatchedRuleID(explanation.MatchedRules, tc.wantRuleID) {
				t.Fatalf("expected matched rule %s in %+v", tc.wantRuleID, explanation.MatchedRules)
			}
			for _, want := range tc.wantEvidence {
				if !strings.Contains(log.ExplanationJSON, want) && !strings.Contains(log.PayloadSnippet, want) && !strings.Contains(log.RuleMessage, want) {
					t.Fatalf("missing evidence %q in log:\nrule=%s\nexplanation=%s\nsnippet=%s", want, log.RuleMessage, log.ExplanationJSON, log.PayloadSnippet)
				}
			}
		})
	}
}

func hasMatchedRuleID(rules []struct {
	ID       int      `json:"id"`
	Evidence []string `json:"evidence"`
}, want string) bool {
	for _, rule := range rules {
		if want == strconv.Itoa(rule.ID) {
			return true
		}
	}
	return false
}

func projectRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("project root with go.mod not found from %s", dir)
		}
		dir = parent
	}
}

package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aegis-waf/internal/auditlog"
	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestT140RequestParserPreviewAndRuntimeLogs(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer upstream.Close()

	detectionEngine, err := detection.NewManager(t.TempDir(), nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	createSite(t, server, "t140", "t140.local", upstream.URL, 5)
	createRule(t, server, `{"ruleId":140001,"name":"t140 xss","category":"custom","variable":"ARGS","operator":"@contains","pattern":"<script>alert(1)</script>","action":"deny","severity":"high","score":6,"source":"custom","enabled":true}`)

	preview := httptest.NewRecorder()
	server.Handler().ServeHTTP(preview, httptest.NewRequest(http.MethodPost, "/api/protection/request-parser/preview", strings.NewReader(`{"method":"POST","uri":"/preview?q=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E","headers":{"Content-Type":"application/json","Cookie":"sid=%255Cu003cscript%255Cu003e"},"body":"{\"profile\":{\"bio\":\"%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E\"}}"}`)))
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var parsed struct {
		Fields []struct {
			Source          string `json:"source"`
			Variable        string `json:"variable"`
			NormalizedValue string `json:"normalizedValue"`
			DecodeSteps     []any  `json:"decodeSteps"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("preview json: %v", err)
	}
	if !hasNormalizedField(parsed.Fields, "query", "ARGS:q", "<script>alert(1)</script>") || !hasNormalizedField(parsed.Fields, "json", "JSON:profile.bio", "<script>alert(1)</script>") {
		t.Fatalf("preview missing normalized query/json fields: %s", preview.Body.String())
	}

	assertWAFStatus(t, server, http.MethodGet, "/search?q=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E", "t140.local", "192.0.2.140:1001", "", http.StatusForbidden, "encoded payload should normalize and block")
	flushAudit(t, server)
	var log database.AttackLog
	if err := db.Order("created_at desc, id desc").First(&log).Error; err != nil {
		t.Fatalf("load attack log: %v", err)
	}
	if !strings.Contains(log.PayloadSnippet, "normalizedRequest") || !strings.Contains(log.PayloadSnippet, "matchedVariable") || !strings.Contains(log.PayloadSnippet, "ARGS:q") {
		t.Fatalf("attack log payload snippet lacks parser explanation: %s", log.PayloadSnippet)
	}
}

func hasNormalizedField(fields []struct {
	Source          string `json:"source"`
	Variable        string `json:"variable"`
	NormalizedValue string `json:"normalizedValue"`
	DecodeSteps     []any  `json:"decodeSteps"`
}, source, variable, want string) bool {
	for _, field := range fields {
		if field.Source == source && field.Variable == variable && strings.Contains(field.NormalizedValue, want) && len(field.DecodeSteps) > 0 {
			return true
		}
	}
	return false
}

func flushAudit(t *testing.T, server *Server) {
	t.Helper()
	if server.audit != nil {
		if err := server.audit.Stop(waitContext(t)); err != nil {
			t.Fatalf("stop audit writer: %v", err)
		}
		server.audit = auditlog.NewWriter(server.db)
	}
}

func waitContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

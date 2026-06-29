package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/crs"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestT136CRSStatusAndReloadAPI(t *testing.T) {
	dir := t.TempDir()
	writeT136Rule(t, dir, "first")
	manager := crs.NewManager(crs.Config{Enabled: true, RulesDir: dir, ParanoiaLevel: 2, InboundThreshold: 6, OutboundThreshold: 7, RequestBodyLimit: 1024})
	detectionEngine, err := detection.NewCorazaEngine(manager)
	if err != nil {
		t.Fatalf("NewCorazaEngine returned error: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, processor, WithDetectionEngine(newReloadRuntime(detectionEngine)), WithCRSManager(manager))

	status := getCRSStatus(t, server, http.MethodGet, "/api/protection/crs/status")
	if !status.Loaded || status.RuleCount != 1 || status.ParanoiaLevel != 2 || status.InboundThreshold != 6 || status.OutboundThreshold != 7 {
		t.Fatalf("unexpected status: %+v", status)
	}
	writeT136Rule(t, dir, "second")
	reloaded := getCRSStatus(t, server, http.MethodPost, "/api/protection/crs/reload")
	if reloaded.RuleCount != 2 {
		t.Fatalf("expected two rules after reload, got %+v", reloaded)
	}
}

type crsAPIStatus struct {
	Loaded            bool `json:"loaded"`
	RuleCount         int  `json:"ruleCount"`
	ParanoiaLevel     int  `json:"paranoiaLevel"`
	InboundThreshold  int  `json:"inboundThreshold"`
	OutboundThreshold int  `json:"outboundThreshold"`
}

type reloadRuntime struct{ detection.Engine }

func newReloadRuntime(engine detection.Engine) *reloadRuntime   { return &reloadRuntime{Engine: engine} }
func (r *reloadRuntime) UpsertRuntimeRule(detection.Rule) error { return nil }
func (r *reloadRuntime) DeleteRuntimeRule(int) error            { return nil }

func getCRSStatus(t *testing.T, server *Server, method, path string) crsAPIStatus {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s %s returned %d: %s", method, path, recorder.Code, recorder.Body.String())
	}
	var status crsAPIStatus
	if err := json.NewDecoder(recorder.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return status
}

func writeT136Rule(t *testing.T, dir, token string) {
	t.Helper()
	path := filepath.Join(dir, token+".conf")
	ruleID := "913001"
	if token == "second" {
		ruleID = "913002"
	}
	content := `SecRule ARGS "@contains ` + token + `" "id:` + ruleID + `,phase:2,deny,log,msg:'` + token + `',severity:'CRITICAL'"`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}
}

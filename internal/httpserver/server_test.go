package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/gateway"
	"aegis-waf/internal/pipeline"
)

type processorStub struct {
	result pipeline.Result
	err    error
	calls  []pipeline.Request
}

func (s *processorStub) Process(_ context.Context, req pipeline.Request) (pipeline.Result, error) {
	s.calls = append(s.calls, req)
	return s.result, s.err
}

func TestHealthzDoesNotCallPipeline(t *testing.T) {
	processor := &processorStub{}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 16}, processor)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if len(processor.calls) != 0 {
		t.Fatalf("healthz called pipeline %d times", len(processor.calls))
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("health status = %q, want ok", body["status"])
	}
}

func TestAllowResponseAndRequestMapping(t *testing.T) {
	processor := &processorStub{result: pipeline.Result{
		Decision:      pipeline.DecisionAllow,
		Reason:        "allowed",
		StageMetrics:  []pipeline.StageMetric{{Stage: pipeline.StageDetection, Duration: 2 * time.Millisecond, Decision: pipeline.DecisionAllow}},
		TotalDuration: 2 * time.Millisecond,
	}}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 64}, processor)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login?q=1", strings.NewReader("select 1"))
	req.Host = "example.test"
	req.RemoteAddr = "192.0.2.10:4567"
	req.Header.Set("User-Agent", "httptest")

	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	if len(processor.calls) != 1 {
		t.Fatalf("pipeline calls = %d, want 1", len(processor.calls))
	}
	got := processor.calls[0]
	if got.Method != http.MethodPost || got.Path != "/login?q=1" || got.Host != "example.test" || got.Body != "select 1" {
		t.Fatalf("unexpected mapped request: %#v", got)
	}
	if !got.RemoteIP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("remote IP = %v, want 192.0.2.10", got.RemoteIP)
	}
	if got.Headers.Get("User-Agent") != "httptest" || len(got.Args["q"]) != 1 || got.Args["q"][0] != "1" {
		t.Fatalf("headers/args not mapped: %#v", got)
	}

	var resp Response
	decodeJSON(t, recorder, &resp)
	if resp.Decision != pipeline.DecisionAllow || resp.Reason != "allowed" || len(resp.Metrics) != 1 {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestBlockResponse(t *testing.T) {
	processor := &processorStub{result: pipeline.Result{
		Decision:       pipeline.DecisionBlock,
		Reason:         "detection blocked request",
		BlockedByStage: pipeline.StageDetection,
		StageMetrics:   []pipeline.StageMetric{{Stage: pipeline.StageDetection, Duration: time.Millisecond, Decision: pipeline.DecisionBlock}},
	}}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 64}, processor)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/blocked", nil)

	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
	}
	var resp Response
	decodeJSON(t, recorder, &resp)
	if resp.Decision != pipeline.DecisionBlock || resp.BlockedByStage != pipeline.StageDetection || resp.Reason == "" {
		t.Fatalf("unexpected block response: %#v", resp)
	}
}

func TestGlobalCaptchaWithoutTriggersChallengesAllRuntimeTraffic(t *testing.T) {
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 64}, &processorStub{})
	server.runtime = runtimeForTest(t, database.Site{ID: 1, Name: "app", Upstream: "http://127.0.0.1:65535", Status: database.SiteStatusEnabled, WAFEnabled: true})
	server.captchaConfig.Store(captchaSettings{ImageCaptcha: true, SliderCaptcha: false, TTLSeconds: 300, MaxAttempts: 5, Triggers: []captchaTrigger{}})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Host = "example.test"
	req.RemoteAddr = "192.0.2.10:12345"

	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", recorder.Code, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/challenge" {
		t.Fatalf("location = %q, want /challenge", location)
	}
}

func TestT124RuntimeSitePolicyIsPassedToPipeline(t *testing.T) {
	processor := &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}
	site := database.Site{ID: 1, Name: "app", Upstream: "http://127.0.0.1:65535", Status: database.SiteStatusEnabled, WAFEnabled: true, BlockScoreThreshold: 9, PolicyMode: database.PolicyModeStandard}
	if err := site.SetRuleGroups([]string{"sqli", "xss"}); err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 64}, processor)
	server.runtime = runtimeForTest(t, site)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login?q=union+select", nil)
	req.Host = "example.test"
	req.RemoteAddr = "192.0.2.10:4567"

	server.Handler().ServeHTTP(recorder, req)

	if len(processor.calls) != 1 {
		t.Fatalf("pipeline calls = %d, want 1; status=%d body=%s", len(processor.calls), recorder.Code, recorder.Body.String())
	}
	got := processor.calls[0]
	if got.BlockScoreThreshold != 9 {
		t.Fatalf("block score threshold = %d, want 9", got.BlockScoreThreshold)
	}
	if !got.EnabledRuleGroups["sqli"] || !got.EnabledRuleGroups["xss"] || got.EnabledRuleGroups["scanner"] {
		t.Fatalf("enabled rule groups = %#v, want only sqli/xss", got.EnabledRuleGroups)
	}
}

func TestBodyLimitReturns413AndDoesNotCallPipeline(t *testing.T) {
	processor := &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 4}, processor)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("12345"))

	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", recorder.Code, recorder.Body.String())
	}
	if len(processor.calls) != 0 {
		t.Fatalf("pipeline calls = %d, want 0", len(processor.calls))
	}
	var resp Response
	decodeJSON(t, recorder, &resp)
	if resp.Decision != pipeline.DecisionBlock || resp.Reason != ErrBodyTooLarge.Error() {
		t.Fatalf("unexpected limit response: %#v", resp)
	}
}

func TestUnavailablePipelineReturns503(t *testing.T) {
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 64}, nil)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
}

func TestRequestBodyParametersEnterDetection(t *testing.T) {
	t.Run("json fields", func(t *testing.T) {
		processor := &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}
		server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, processor)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/json-api/order?source=query", strings.NewReader(`{"filter":{"q":"%253Cscript%253E"},"ids":[1,2],"active":true}`))
		req.Header.Set("Content-Type", "application/json")

		server.Handler().ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
		}
		if len(processor.calls) != 1 {
			t.Fatalf("pipeline calls = %d, want 1", len(processor.calls))
		}
		got := processor.calls[0]
		if got.Body == "" || !strings.Contains(got.Body, `%253Cscript%253E`) {
			t.Fatalf("raw body not preserved: %q", got.Body)
		}
		if firstArg(got.Args, "source") != "query" || firstArg(got.Args, "filter.q") != "%253Cscript%253E" || firstArg(got.Args, "ids") != "1" || got.Args["ids"][1] != "2" || firstArg(got.Args, "active") != "true" {
			t.Fatalf("json args not mapped: %#v", got.Args)
		}
	})

	t.Run("multipart fields and file metadata", func(t *testing.T) {
		processor := &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}
		server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 4096}, processor)
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.WriteField("comment", "un/**/ion%20select"); err != nil {
			t.Fatal(err)
		}
		part, err := writer.CreateFormFile("upload", "../../shell.php")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte("safe file content")); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body.Bytes()))
		req.Header.Set("Content-Type", writer.FormDataContentType())

		server.Handler().ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
		}
		if len(processor.calls) != 1 {
			t.Fatalf("pipeline calls = %d, want 1", len(processor.calls))
		}
		got := processor.calls[0]
		if got.Body == "" || !strings.Contains(got.Body, "safe file content") {
			t.Fatalf("raw multipart body not preserved")
		}
		if firstArg(got.Args, "comment") != "un/**/ion%20select" || firstArg(got.Args, "upload") != "shell.php" {
			t.Fatalf("multipart args not mapped: %#v", got.Args)
		}
	})
}

func TestT123BodyParametersReachRealDetection(t *testing.T) {
	dir := t.TempDir()
	rules := `SecRule ARGS "@contains <script" "id:941100,phase:2,deny,status:403,msg:'XSS script tag'"
SecRule ARGS "@contains union select" "id:942100,phase:2,deny,status:403,msg:'SQL injection attempt'"`
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-T123.conf"), []byte(rules), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	manager, err := detection.NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	processor := pipeline.New(pipeline.Config{FailOpen: false}, pipeline.WithDetection(manager))

	t.Run("json encoded xss", func(t *testing.T) {
		server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 2048}, processor)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/json-api/order", strings.NewReader(`{"filter":{"q":"%253Cscript%253Ealert(1)%253C/script%253E"}}`))
		req.Header.Set("Content-Type", "application/json")

		server.Handler().ServeHTTP(recorder, req)

		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("multipart encoded sqli", func(t *testing.T) {
		server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 4096}, processor)
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.WriteField("comment", "un/**/ion%20sel/**/ect password"); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body.Bytes()))
		req.Header.Set("Content-Type", writer.FormDataContentType())

		server.Handler().ServeHTTP(recorder, req)

		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestAddrUsesConfig(t *testing.T) {
	server := New(config.ServerConfig{Host: "127.0.0.1", Port: 9090}, config.SecurityConfig{}, &processorStub{})
	if server.Addr() != "127.0.0.1:9090" {
		t.Fatalf("addr = %q, want 127.0.0.1:9090", server.Addr())
	}
}

func runtimeForTest(t *testing.T, site database.Site) *gateway.RuntimeManager {
	t.Helper()
	if len(site.Domains()) == 0 {
		if err := site.SetDomains([]string{"example.test"}); err != nil {
			t.Fatalf("set test site domains: %v", err)
		}
	}
	manager, err := gateway.NewRuntimeManager(siteListFunc(func(context.Context) ([]database.Site, error) {
		return []database.Site{site}, nil
	}))
	if err != nil {
		t.Fatalf("create runtime manager: %v", err)
	}
	return manager
}

type siteListFunc func(context.Context) ([]database.Site, error)

func (f siteListFunc) List(ctx context.Context) ([]database.Site, error) {
	return f(ctx)
}

func firstArg(args map[string][]string, key string) string {
	if len(args[key]) == 0 {
		return ""
	}
	return args[key][0]
}

func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder, value any) {
	t.Helper()
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), value); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, recorder.Body.String())
	}
}

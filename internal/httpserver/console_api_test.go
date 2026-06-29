package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
)

func TestConsoleDashboardAPI(t *testing.T) {
	server := New(config.ServerConfig{Host: "127.0.0.1", Port: 9090, Mode: "debug"}, config.SecurityConfig{MaxBodySize: 1024, EnableSemantic: true}, &processorStub{})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/overview", nil)

	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("missing cors header")
	}
	var body dashboardOverview
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if body.Status.Service != "Aegis-WAF" || len(body.Metrics) == 0 || len(body.Pipeline) == 0 {
		t.Fatalf("unexpected dashboard body: %#v", body)
	}
}

func TestConsoleAPIRoutes(t *testing.T) {
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{})
	paths := []string{
		"/api/sites",
		"/api/attack-logs",
		"/api/access-rules",
		"/api/cc-protection",
		"/api/captcha",
		"/api/settings",
		"/api/semantic-fingerprints",
		"/api/protection/site-policies",
		"/api/protection/rule-sets",
		"/api/protection/crs/status",
		"/api/protection/rules",
		"/api/protection/whitelists",
		"/api/protection/cc-policies",
		"/api/protection/cc-events",
		"/api/protection/semantic-fingerprints",
		"/api/protection/traffic/overview",
		"/api/protection/traffic/trend",
		"/api/protection/traffic/top-ip",
		"/api/protection/traffic/top-path",
		"/api/protection/traffic/status-codes",
		"/api/protection/traffic/sites",
		"/api/protection/attack-events",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			server.Handler().ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
			}
			if recorder.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("content-type = %q, want application/json", recorder.Header().Get("Content-Type"))
			}
		})
	}
}

func TestConsoleAPIOptionsAndNotFound(t *testing.T) {
	server := New(config.ServerConfig{}, config.SecurityConfig{}, &processorStub{})

	optionsRecorder := httptest.NewRecorder()
	optionsReq := httptest.NewRequest(http.MethodOptions, "/api/sites", nil)
	server.Handler().ServeHTTP(optionsRecorder, optionsReq)
	if optionsRecorder.Code != http.StatusNoContent {
		t.Fatalf("options status = %d, want 204", optionsRecorder.Code)
	}

	notFoundRecorder := httptest.NewRecorder()
	notFoundReq := httptest.NewRequest(http.MethodGet, "/api/missing", nil)
	server.Handler().ServeHTTP(notFoundRecorder, notFoundReq)
	if notFoundRecorder.Code != http.StatusNotFound {
		t.Fatalf("not found status = %d, want 404", notFoundRecorder.Code)
	}
}

func TestProtectionRequestParserPreviewRoute(t *testing.T) {
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{})
	body := `{"rawRequest":"GET /login?next=%2Fadmin HTTP/1.1\nHost: example.test\nCookie: sid=abc\n\n"}`
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/protection/request-parser/preview", strings.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	var preview requestParserPreviewResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.NormalizedURI != "/login" || preview.NormalizedQuery != "next=%2Fadmin" || preview.Headers["Host"] != "example.test" || preview.Cookies["sid"] != "abc" {
		t.Fatalf("unexpected parser preview: %#v", preview)
	}
}

func TestPolicyWriteAPIs(t *testing.T) {
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{})

	accessBody := `{"type":"ip_blacklist","value":"10.1.2.3","description":"bad ip","status":"enabled"}`
	accessCreate := httptest.NewRecorder()
	server.Handler().ServeHTTP(accessCreate, httptest.NewRequest(http.MethodPost, "/api/access-rules", strings.NewReader(accessBody)))
	if accessCreate.Code != http.StatusServiceUnavailable {
		t.Fatalf("access create without db status = %d, want 503", accessCreate.Code)
	}

	captchaBody := `{"imageCaptcha":true,"sliderCaptcha":false,"ttlSeconds":600,"maxAttempts":3,"triggers":[{"id":"t1","name":"CC Challenge","condition":"cc_action == captcha","method":"button","enabled":true}]}`
	captchaSave := httptest.NewRecorder()
	server.Handler().ServeHTTP(captchaSave, httptest.NewRequest(http.MethodPut, "/api/captcha", strings.NewReader(captchaBody)))
	if captchaSave.Code != http.StatusOK {
		t.Fatalf("captcha save status = %d, want 200; body=%s", captchaSave.Code, captchaSave.Body.String())
	}
	captchaGet := httptest.NewRecorder()
	server.Handler().ServeHTTP(captchaGet, httptest.NewRequest(http.MethodGet, "/api/captcha", nil))
	if captchaGet.Code != http.StatusOK || !strings.Contains(captchaGet.Body.String(), "CC Challenge") {
		t.Fatalf("captcha get did not return saved config: status=%d body=%s", captchaGet.Code, captchaGet.Body.String())
	}
}

package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"aegis-waf/internal/config"
)

func TestT149SecurityCoverageAPI(t *testing.T) {
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/protection/security-coverage", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/protection/security-coverage returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		AttackTotal           int     `json:"attackTotal"`
		AttackBlocked         int     `json:"attackBlocked"`
		AttackBlockRate       float64 `json:"attackBlockRate"`
		BenignFalsePositives  int     `json:"benignFalsePositives"`
		AttackBlockRateTarget float64 `json:"attackBlockRateTarget"`
		FalsePositiveLimit    int     `json:"falsePositiveLimit"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.AttackTotal < 30 || payload.AttackBlockRate < 0.90 || payload.BenignFalsePositives > 3 {
		t.Fatalf("unexpected coverage payload: %+v", payload)
	}
	if payload.AttackBlockRateTarget != 0.90 || payload.FalsePositiveLimit != 3 {
		t.Fatalf("unexpected coverage gates: %+v", payload)
	}
}

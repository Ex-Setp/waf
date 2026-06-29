package cc

import (
	"testing"
	"time"

	"aegis-waf/internal/database"
)

func TestLimiterBlocksBySiteIPPath(t *testing.T) {
	limiter := NewLimiter()
	now := time.Unix(100, 0)
	limiter.SetClock(func() time.Time { return now })
	policy := database.CCPolicy{SiteID: 7, Scope: "/login", Threshold: 2, WindowSeconds: 60, Action: database.CCActionBlock, Enabled: true}
	req := Request{SiteID: 7, SourceIP: "192.0.2.10", Path: "/login"}
	if got := limiter.Evaluate(req, []database.CCPolicy{policy}); got.Decision != DecisionAllow || got.Key != "7:192.0.2.10:/login" {
		t.Fatalf("first=%#v", got)
	}
	if got := limiter.Evaluate(req, []database.CCPolicy{policy}); got.Decision != DecisionAllow {
		t.Fatalf("second=%#v", got)
	}
	if got := limiter.Evaluate(req, []database.CCPolicy{policy}); got.Decision != DecisionBlock {
		t.Fatalf("third=%#v", got)
	}
}

func TestLimiterCaptchaAction(t *testing.T) {
	limiter := NewLimiter()
	policy := database.CCPolicy{Scope: "*", Threshold: 1, WindowSeconds: 60, Action: database.CCActionCaptcha, Enabled: true}
	limiter.Evaluate(Request{Path: "/"}, []database.CCPolicy{policy})
	if got := limiter.Evaluate(Request{Path: "/"}, []database.CCPolicy{policy}); got.Decision != DecisionCaptcha {
		t.Fatalf("decision=%s", got.Decision)
	}
}

package cc

import (
	"testing"
	"time"

	"aegis-waf/internal/database"
)

func TestLimiterT125SupportsMultidimensionalKeys(t *testing.T) {
	limiter := NewLimiter()
	limiter.SetClock(func() time.Time { return time.Unix(100, 0) })
	policies := []database.CCPolicy{
		{Name: "site", Scope: "site", Threshold: 1, WindowSeconds: 60, Action: database.CCActionBlock, Enabled: true},
		{Name: "ua", Scope: "ua", Threshold: 1, WindowSeconds: 60, Action: database.CCActionBlock, Enabled: true},
	}

	firstPath := limiter.Evaluate(Request{SiteID: 7, SourceIP: "192.0.2.10", Path: "/a", UserAgent: "bot/1"}, policies)
	secondPath := limiter.Evaluate(Request{SiteID: 7, SourceIP: "192.0.2.10", Path: "/b", UserAgent: "bot/1"}, policies)
	if firstPath.Decision != DecisionAllow || secondPath.Decision != DecisionBlock || secondPath.Policy.Name != "site" {
		t.Fatalf("site dimension decisions: first=%#v second=%#v", firstPath, secondPath)
	}
	if secondPath.Key != "site:7:192.0.2.10" {
		t.Fatalf("site key=%q", secondPath.Key)
	}

	otherSite := limiter.Evaluate(Request{SiteID: 8, SourceIP: "192.0.2.10", Path: "/b", UserAgent: "bot/1"}, policies)
	if otherSite.Decision != DecisionAllow {
		t.Fatalf("site key should isolate site ids: %#v", otherSite)
	}

	uaPolicy := []database.CCPolicy{{Name: "ua", Scope: "ua", Threshold: 1, WindowSeconds: 60, Action: database.CCActionBlock, Enabled: true}}
	limiter = NewLimiter()
	limiter.SetClock(func() time.Time { return time.Unix(100, 0) })
	firstUA := limiter.Evaluate(Request{SiteID: 7, SourceIP: "192.0.2.20", Path: "/a", UserAgent: "scanner/1"}, uaPolicy)
	secondUA := limiter.Evaluate(Request{SiteID: 7, SourceIP: "192.0.2.20", Path: "/b", UserAgent: "scanner/1"}, uaPolicy)
	if firstUA.Decision != DecisionAllow || secondUA.Decision != DecisionBlock || secondUA.Key != "ua:7:192.0.2.20:scanner/1" {
		t.Fatalf("ua dimension decisions: first=%#v second=%#v", firstUA, secondUA)
	}
}

func TestLimiterT125LoginFailureAndNotFoundScanScopes(t *testing.T) {
	limiter := NewLimiter()
	limiter.SetClock(func() time.Time { return time.Unix(100, 0) })
	loginPolicy := database.CCPolicy{Name: "login failures", Scope: "login-failure:/login", Threshold: 1, WindowSeconds: 60, Action: database.CCActionCaptcha, Enabled: true}

	if got := limiter.Evaluate(Request{SiteID: 1, SourceIP: "203.0.113.10", Path: "/login", StatusCode: 200}, []database.CCPolicy{loginPolicy}); got.Decision != DecisionAllow || got.Count != 0 {
		t.Fatalf("successful login should not count: %#v", got)
	}
	limiter.Evaluate(Request{SiteID: 1, SourceIP: "203.0.113.10", Path: "/login", StatusCode: 401}, []database.CCPolicy{loginPolicy})
	if got := limiter.Evaluate(Request{SiteID: 1, SourceIP: "203.0.113.10", Path: "/login", StatusCode: 403}, []database.CCPolicy{loginPolicy}); got.Decision != DecisionCaptcha || got.Key != "login-failure:1:203.0.113.10:/login" {
		t.Fatalf("login failures should trigger captcha: %#v", got)
	}

	limiter = NewLimiter()
	limiter.SetClock(func() time.Time { return time.Unix(100, 0) })
	notFoundPolicy := database.CCPolicy{Name: "404 scan", Scope: "404", Threshold: 2, WindowSeconds: 60, Action: database.CCActionBlock, Enabled: true}
	for i := 0; i < 2; i++ {
		if got := limiter.Evaluate(Request{SiteID: 1, SourceIP: "203.0.113.11", Path: "/missing", StatusCode: 404}, []database.CCPolicy{notFoundPolicy}); got.Decision != DecisionAllow {
			t.Fatalf("404 warmup %d: %#v", i, got)
		}
	}
	if got := limiter.Evaluate(Request{SiteID: 1, SourceIP: "203.0.113.11", Path: "/also-missing", StatusCode: 404}, []database.CCPolicy{notFoundPolicy}); got.Decision != DecisionBlock || got.Key != "404:1:203.0.113.11" {
		t.Fatalf("404 scan should aggregate by site+ip: %#v", got)
	}
}

func TestLimiterT125ActionChainEscalatesAndExpiresBlocks(t *testing.T) {
	limiter := NewLimiter()
	now := time.Unix(100, 0)
	limiter.SetClock(func() time.Time { return now })
	policy := database.CCPolicy{Name: "chain", Scope: "site", Threshold: 1, WindowSeconds: 3600, Action: database.CCActionObserve + ">" + database.CCActionCaptcha + ">" + database.CCActionTempBlock + ">" + database.CCActionLongBlock, Enabled: true}
	req := Request{SiteID: 9, SourceIP: "198.51.100.99", Path: "/", UserAgent: "bot/2"}

	if got := limiter.Evaluate(req, []database.CCPolicy{policy}); got.Decision != DecisionAllow {
		t.Fatalf("warmup=%#v", got)
	}
	if got := limiter.Evaluate(req, []database.CCPolicy{policy}); got.Decision != DecisionObserve {
		t.Fatalf("first violation should observe: %#v", got)
	}
	if got := limiter.Evaluate(req, []database.CCPolicy{policy}); got.Decision != DecisionCaptcha {
		t.Fatalf("second violation should captcha: %#v", got)
	}
	blocked := limiter.Evaluate(req, []database.CCPolicy{policy})
	if blocked.Decision != DecisionTempBlock || blocked.BlockUntil.IsZero() || blocked.BlockUntil.Sub(now) != DefaultTempBlockDuration {
		t.Fatalf("third violation should temp-block with expiry: %#v", blocked)
	}
	if got := limiter.Evaluate(req, []database.CCPolicy{policy}); got.Decision != DecisionTempBlock || got.Count != blocked.Count {
		t.Fatalf("active temp block should short-circuit without counting: %#v", got)
	}

	now = blocked.BlockUntil.Add(time.Second)
	if got := limiter.Evaluate(req, []database.CCPolicy{policy}); got.Decision != DecisionLongBlock || got.BlockUntil.Sub(now) != DefaultLongBlockDuration {
		t.Fatalf("post-temp next violation should long-block: %#v", got)
	}
}

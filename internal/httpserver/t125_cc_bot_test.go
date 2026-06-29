package httpserver

import (
	"net"
	"testing"

	"aegis-waf/internal/cc"
	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/gateway"
	"aegis-waf/internal/pipeline"
)

func TestT125EvaluateCCPassesUserAgentDimension(t *testing.T) {
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 64}, &processorStub{})
	server.policies.Store(policySnapshot{CCPolicies: []database.CCPolicy{{Name: "ua", Scope: "ua", Threshold: 1, WindowSeconds: 60, Action: database.CCActionBlock, Enabled: true}}})
	site := &gateway.SiteRuntime{ID: 3}
	req := pipeline.Request{RemoteIP: net.ParseIP("192.0.2.44"), Path: "/one", Headers: make(map[string][]string)}
	req.Headers.Set("User-Agent", "samebot/1")

	first := server.evaluateCC(nil, site, req)
	req.Path = "/two"
	second := server.evaluateCC(nil, site, req)
	if first.Decision != cc.DecisionAllow || second.Decision != cc.DecisionBlock || second.Key != "ua:3:192.0.2.44:samebot/1" {
		t.Fatalf("ua dimension not enforced through server: first=%#v second=%#v", first, second)
	}
}

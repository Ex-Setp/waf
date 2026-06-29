package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/pipeline"
)

type errorProcessor struct{}

func (errorProcessor) Process(context.Context, pipeline.Request) (pipeline.Result, error) {
	return pipeline.Result{Decision: pipeline.DecisionAllow}, fmt.Errorf("detector offline")
}

func TestT127FailOpenAndFailClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("origin")) }))
	defer upstream.Close()

	for _, tc := range []struct {
		name     string
		failOpen bool
		want     int
		body     string
	}{
		{"fail-open", true, http.StatusOK, "origin"},
		{"fail-closed", false, http.StatusServiceUnavailable, "fail-closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testDB(t)
			site := database.Site{Name: "app", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: true}
			_ = site.SetDomains([]string{"t127.local"})
			if err := db.Create(&site).Error; err != nil {
				t.Fatal(err)
			}
			server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024, FailOpen: tc.failOpen}, errorProcessor{}, WithDatabase(db))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = "t127.local"
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.body) {
				t.Fatalf("status/body=%d %q", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestT127UpstreamRetryAndHealth(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("recovered"))
	}))
	defer upstream.Close()
	db := testDB(t)
	site := database.Site{Name: "app", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: false}
	_ = site.SetDomains([]string{"retry.local"})
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024, UpstreamRetries: 1, UpstreamTimeoutMS: 500}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}, WithDatabase(db))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "retry.local"
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "recovered" || calls != 2 {
		t.Fatalf("retry status/body/calls=%d %q %d", rec.Code, rec.Body.String(), calls)
	}

	health := httptest.NewRecorder()
	server.Handler().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/upstreams/health", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), "healthy") {
		t.Fatalf("health=%d %s", health.Code, health.Body.String())
	}
}

func TestT127BackupRollbackEmergencyBypassAndSiteDisable(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("bypass ok")) }))
	defer upstream.Close()
	site := database.Site{Name: "app", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: true}
	_ = site.SetDomains([]string{"safe.local"})
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&database.AccessRule{SiteID: site.ID, Type: database.AccessRuleRuleDisable, Value: "942100", Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, blockProcessor{}, WithDatabase(db))

	backup := httptest.NewRecorder()
	server.Handler().ServeHTTP(backup, httptest.NewRequest(http.MethodPost, "/api/safety/backups", nil))
	if backup.Code != http.StatusCreated {
		t.Fatalf("backup=%d %s", backup.Code, backup.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(backup.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := int(created["id"].(float64))

	disable := httptest.NewRecorder()
	server.Handler().ServeHTTP(disable, httptest.NewRequest(http.MethodPost, "/api/sites/1/disable", nil))
	if disable.Code != http.StatusOK {
		t.Fatalf("disable=%d %s", disable.Code, disable.Body.String())
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "safe.local"
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled waf status=%d", rec.Code)
	}

	rb := httptest.NewRecorder()
	server.Handler().ServeHTTP(rb, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/safety/backups/%d/rollback", id), nil))
	if rb.Code != http.StatusOK {
		t.Fatalf("rollback=%d %s", rb.Code, rb.Body.String())
	}
	var restored database.Site
	if err := db.First(&restored, site.ID).Error; err != nil || restored.Status != database.SiteStatusEnabled {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}

	var rule database.AccessRule
	if err := db.First(&rule).Error; err != nil {
		t.Fatal(err)
	}
	rule.Enabled = false
	if err := db.Save(&rule).Error; err != nil {
		t.Fatal(err)
	}
	rrb := httptest.NewRecorder()
	server.Handler().ServeHTTP(rrb, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/safety/backups/%d/rules/rollback", id), nil))
	if rrb.Code != http.StatusOK {
		t.Fatalf("rule rollback=%d %s", rrb.Code, rrb.Body.String())
	}
	var restoredRule database.AccessRule
	if err := db.First(&restoredRule, rule.ID).Error; err != nil || !restoredRule.Enabled {
		t.Fatalf("restored rule=%+v err=%v", restoredRule, err)
	}

	emergency := httptest.NewRecorder()
	server.Handler().ServeHTTP(emergency, httptest.NewRequest(http.MethodPost, "/api/safety/emergency-bypass", strings.NewReader(`{"enabled":true}`)))
	if emergency.Code != http.StatusOK {
		t.Fatalf("emergency=%d %s", emergency.Code, emergency.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "safe.local"
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "bypass ok" {
		t.Fatalf("bypass=%d %q", rec.Code, rec.Body.String())
	}
}

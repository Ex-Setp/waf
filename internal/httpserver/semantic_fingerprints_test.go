package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/gateway"
	"aegis-waf/internal/pipeline"
)

func TestSemanticFingerprintAPILifecycle(t *testing.T) {
	db, err := database.Open(config.DatabaseConfig{Driver: database.DriverSQLite, DSN: ":memory:"})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, &processorStub{}, WithDatabase(db))

	fp := database.SemanticFingerprint{Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Language: "sql", Skeleton: "(select (union))", SamplePayload: "select a union select b", Action: "log", Status: database.SemanticFingerprintStatusObserving, Hits: 2, Source: "test", XDPSyncStatus: "not_required"}
	if err := db.Create(&fp).Error; err != nil {
		t.Fatalf("seed fingerprint: %v", err)
	}

	list := httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/semantic-fingerprints", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	var listed semanticFingerprintAPIResponse
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listed.Total != 1 || listed.Fingerprints[0].Skeleton == "" {
		t.Fatalf("unexpected list: %#v", listed)
	}

	activate := httptest.NewRecorder()
	server.Handler().ServeHTTP(activate, httptest.NewRequest(http.MethodPost, "/api/semantic-fingerprints/1/activate", nil))
	if activate.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", activate.Code, activate.Body.String())
	}
	var active semanticFingerprintEntry
	if err := json.Unmarshal(activate.Body.Bytes(), &active); err != nil {
		t.Fatalf("decode activate: %v", err)
	}
	if active.Status != database.SemanticFingerprintStatusActive || active.Action != "deny" || active.RuleID == 0 || !strings.Contains(active.GeneratedRule, active.Hash) {
		t.Fatalf("fingerprint was not activated: %#v", active)
	}

	rollback := httptest.NewRecorder()
	server.Handler().ServeHTTP(rollback, httptest.NewRequest(http.MethodPost, "/api/semantic-fingerprints/1/rollback", nil))
	if rollback.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollback.Code, rollback.Body.String())
	}
	var rolled semanticFingerprintEntry
	if err := json.Unmarshal(rollback.Body.Bytes(), &rolled); err != nil {
		t.Fatalf("decode rollback: %v", err)
	}
	if rolled.Status != database.SemanticFingerprintStatusRollback || rolled.Action != "pass" {
		t.Fatalf("fingerprint was not rolled back: %#v", rolled)
	}
}

func TestSemanticDetectionUpsertsFingerprintFromRealPipelineResult(t *testing.T) {
	db, err := database.Open(config.DatabaseConfig{Driver: database.DriverSQLite, DSN: ":memory:"})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, &processorStub{}, WithDatabase(db))
	site := &gateway.SiteRuntime{ID: 1, Name: "demo"}
	req := pipeline.Request{Path: "/search?q=1", Args: map[string][]string{"q": []string{"select name from users union select password from secrets"}}}
	result := pipeline.Result{Semantic: detection.Result{Matches: []detection.MatchedRule{{ID: detection.SemanticSQLTaintRuleID, Message: "semantic SQL taint"}}}}

	server.observeSemanticFingerprints(context.Background(), site.ID, site.Name, req, result)
	server.observeSemanticFingerprints(context.Background(), site.ID, site.Name, req, result)
	server.observeSemanticFingerprints(context.Background(), site.ID, site.Name, req, result)

	var fps []database.SemanticFingerprint
	if err := db.Find(&fps).Error; err != nil {
		t.Fatalf("list fingerprints: %v", err)
	}
	var sqlFP *database.SemanticFingerprint
	for i := range fps {
		if fps[i].Language == "sql" {
			sqlFP = &fps[i]
			break
		}
	}
	if sqlFP == nil {
		t.Fatalf("expected SQL fingerprint, got %#v", fps)
	}
	if sqlFP.Hits != 3 || sqlFP.Status != database.SemanticFingerprintStatusActive || sqlFP.GeneratedRule == "" || sqlFP.Skeleton == "" {
		t.Fatalf("fingerprint did not auto-promote from semantic observations: %#v", *sqlFP)
	}
}

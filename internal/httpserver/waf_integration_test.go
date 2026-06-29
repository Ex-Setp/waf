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

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type blockProcessor struct{}

func (blockProcessor) Process(context.Context, pipeline.Request) (pipeline.Result, error) {
	return pipeline.Result{Decision: pipeline.DecisionBlock, Reason: "blocked", BlockedByStage: pipeline.StageDetection}, nil
}

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSitesCRUDUsesDatabase(t *testing.T) {
	db := testDB(t)
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}, WithDatabase(db))

	post := httptest.NewRecorder()
	server.Handler().ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(`{"name":"test","domains":["test.local"],"upstream":"http://127.0.0.1:8081","wafEnabled":true}`)))
	if post.Code != http.StatusCreated {
		t.Fatalf("post=%d %s", post.Code, post.Body.String())
	}

	get := httptest.NewRecorder()
	server.Handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/sites", nil))
	var list siteListResponse
	if err := json.Unmarshal(get.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Summary.Total != 1 || list.Sites[0].Domains[0] != "test.local" {
		t.Fatalf("list=%#v", list)
	}

	put := httptest.NewRecorder()
	server.Handler().ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/api/sites/1", strings.NewReader(`{"name":"test","domains":["test.local"],"upstream":"http://127.0.0.1:8082","wafEnabled":true}`)))
	if put.Code != http.StatusOK {
		t.Fatalf("put=%d %s", put.Code, put.Body.String())
	}

	del := httptest.NewRecorder()
	server.Handler().ServeHTTP(del, httptest.NewRequest(http.MethodDelete, "/api/sites/1", nil))
	if del.Code != http.StatusOK {
		t.Fatalf("delete=%d %s", del.Code, del.Body.String())
	}
}

func TestAllowRequestProxiesAndWritesAccessLog(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-For"); got != "192.0.2.10" {
			t.Fatalf("xff=%q", got)
		}
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()
	site := database.Site{Name: "test", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: true}
	_ = site.SetDomains([]string{"test.local"})
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}, WithDatabase(db))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	req.Host = "test.local"
	req.RemoteAddr = "192.0.2.10:1234"
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "upstream ok" {
		t.Fatalf("proxy=%d %s", rec.Code, rec.Body.String())
	}
	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var count int64
	if err := db.Model(&database.AccessLog{}).Where("decision = ?", "allow").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("access logs=%d err=%v", count, err)
	}
	logsRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(logsRecorder, httptest.NewRequest(http.MethodGet, "/api/access-logs?host=test.local&page=1&pageSize=10", nil))
	if logsRecorder.Code != http.StatusOK {
		t.Fatalf("access logs api status=%d body=%s", logsRecorder.Code, logsRecorder.Body.String())
	}
	var logs accessLogResponse
	if err := json.Unmarshal(logsRecorder.Body.Bytes(), &logs); err != nil {
		t.Fatalf("decode access logs: %v", err)
	}
	if logs.Total != 1 || logs.Logs[0].Host != "test.local" || logs.Logs[0].Decision != "allow" {
		t.Fatalf("access logs api=%#v", logs)
	}
}

func TestHotReloadSiteAndPolicyChangesWithoutRestart(t *testing.T) {
	db := testDB(t)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("first")) }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("second")) }))
	defer second.Close()
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}, WithDatabase(db))

	post := httptest.NewRecorder()
	server.Handler().ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(fmt.Sprintf(`{"name":"hot","domains":["hot.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"semanticProtection":false}`, first.URL))))
	if post.Code != http.StatusCreated {
		t.Fatalf("post=%d %s", post.Code, post.Body.String())
	}
	firstResp := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodGet, "/", nil)
	firstReq.Host = "hot.local"
	server.Handler().ServeHTTP(firstResp, firstReq)
	if firstResp.Body.String() != "first" {
		t.Fatalf("first upstream response=%q", firstResp.Body.String())
	}

	put := httptest.NewRecorder()
	server.Handler().ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/api/sites/1", strings.NewReader(fmt.Sprintf(`{"name":"hot","domains":["hot.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"semanticProtection":false}`, second.URL))))
	if put.Code != http.StatusOK {
		t.Fatalf("put=%d %s", put.Code, put.Body.String())
	}
	secondResp := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodGet, "/", nil)
	secondReq.Host = "hot.local"
	server.Handler().ServeHTTP(secondResp, secondReq)
	if secondResp.Body.String() != "second" {
		t.Fatalf("second upstream response=%q", secondResp.Body.String())
	}

	if err := db.Create(&database.AccessRule{Type: database.AccessRuleIPBlacklist, Value: "192.0.2.10", Enabled: true}).Error; err != nil {
		t.Fatalf("create access rule: %v", err)
	}
	if err := server.reloadPolicies(context.Background()); err != nil {
		t.Fatalf("reloadPolicies: %v", err)
	}
	blocked := httptest.NewRecorder()
	blockedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	blockedReq.Host = "hot.local"
	blockedReq.RemoteAddr = "192.0.2.10:1234"
	server.Handler().ServeHTTP(blocked, blockedReq)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("access rule did not hot reload: status=%d body=%s", blocked.Code, blocked.Body.String())
	}

	del := httptest.NewRecorder()
	server.Handler().ServeHTTP(del, httptest.NewRequest(http.MethodDelete, "/api/sites/1", nil))
	if del.Code != http.StatusOK {
		t.Fatalf("delete site=%d %s", del.Code, del.Body.String())
	}
	missing := httptest.NewRecorder()
	missingReq := httptest.NewRequest(http.MethodGet, "/", nil)
	missingReq.Host = "hot.local"
	server.Handler().ServeHTTP(missing, missingReq)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("deleted host still routed: status=%d body=%s", missing.Code, missing.Body.String())
	}
}

func TestBlockRequestWritesAttackLogAndDashboard(t *testing.T) {
	db := testDB(t)
	site := database.Site{Name: "test", Upstream: "http://127.0.0.1:1", Status: database.SiteStatusEnabled, WAFEnabled: true}
	_ = site.SetDomains([]string{"test.local"})
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, blockProcessor{}, WithDatabase(db))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/blocked", nil)
	req.Host = "test.local"
	req.RemoteAddr = "192.0.2.10:1234"
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	logs := httptest.NewRecorder()
	server.Handler().ServeHTTP(logs, httptest.NewRequest(http.MethodGet, "/api/attack-logs", nil))
	var attack attackLogResponse
	if err := json.Unmarshal(logs.Body.Bytes(), &attack); err != nil {
		t.Fatal(err)
	}
	if attack.Total != 1 || attack.Logs[0].Stage != pipeline.StageDetection {
		t.Fatalf("attack=%#v", attack)
	}

	dash := httptest.NewRecorder()
	server.Handler().ServeHTTP(dash, httptest.NewRequest(http.MethodGet, "/api/dashboard/overview", nil))
	var overview dashboardOverview
	if err := json.Unmarshal(dash.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if overview.Metrics[0].Value != 1 || overview.Metrics[1].Value != 1 {
		t.Fatalf("overview=%#v", overview.Metrics)
	}
}

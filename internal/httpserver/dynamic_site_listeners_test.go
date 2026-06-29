package httpserver

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/pipeline"
)

func TestSiteListenersFollowEnabledSitePorts(t *testing.T) {
	db := testDB(t)
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}, WithDatabase(db))

	create123 := httptest.NewRecorder()
	server.Handler().ServeHTTP(create123, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(`{"name":"a","domains":["a.local"],"upstream":"http://127.0.0.1:8081","listenPort":123,"status":"enabled","tlsMode":"off","wafEnabled":true}`)))
	if create123.Code != http.StatusCreated {
		t.Fatalf("create123=%d %s", create123.Code, create123.Body.String())
	}
	assertSiteListenerPorts(t, server, []int{123})

	create223 := httptest.NewRecorder()
	server.Handler().ServeHTTP(create223, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(`{"name":"b","domains":["b.local"],"upstream":"http://127.0.0.1:8082","listenPort":223,"status":"enabled","tlsMode":"off","wafEnabled":true}`)))
	if create223.Code != http.StatusCreated {
		t.Fatalf("create223=%d %s", create223.Code, create223.Body.String())
	}
	assertSiteListenerPorts(t, server, []int{123, 223})

	move123To223 := httptest.NewRecorder()
	server.Handler().ServeHTTP(move123To223, httptest.NewRequest(http.MethodPut, "/api/sites/1", strings.NewReader(`{"name":"a","domains":["a.local"],"upstream":"http://127.0.0.1:8081","listenPort":223,"status":"enabled","tlsMode":"off","wafEnabled":true}`)))
	if move123To223.Code != http.StatusOK {
		t.Fatalf("move123To223=%d %s", move123To223.Code, move123To223.Body.String())
	}
	assertSiteListenerPorts(t, server, []int{223})

	disable223 := httptest.NewRecorder()
	server.Handler().ServeHTTP(disable223, httptest.NewRequest(http.MethodPut, "/api/sites/2", strings.NewReader(`{"name":"b","domains":["b.local"],"upstream":"http://127.0.0.1:8082","listenPort":223,"status":"disabled","tlsMode":"off","wafEnabled":true}`)))
	if disable223.Code != http.StatusOK {
		t.Fatalf("disable223=%d %s", disable223.Code, disable223.Body.String())
	}
	assertSiteListenerPorts(t, server, []int{223})

	deleteLast223 := httptest.NewRecorder()
	server.Handler().ServeHTTP(deleteLast223, httptest.NewRequest(http.MethodDelete, "/api/sites/1", nil))
	if deleteLast223.Code != http.StatusOK {
		t.Fatalf("deleteLast223=%d %s", deleteLast223.Code, deleteLast223.Body.String())
	}
	assertSiteListenerPorts(t, server, nil)
}

func assertSiteListenerPorts(t *testing.T, server *Server, want []int) {
	t.Helper()
	got := server.SiteListenerPorts()
	sort.Ints(got)
	if len(got) != len(want) {
		t.Fatalf("site listener ports = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("site listener ports = %v, want %v", got, want)
		}
	}
}

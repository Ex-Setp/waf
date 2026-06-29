package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/pipeline"
)

func TestT135CCBotRuntimeClosure(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing-a", "/missing-b":
			http.NotFound(w, r)
		case "/login":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("login failed"))
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer upstream.Close()

	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 2048}, pipeline.New(pipeline.Config{}), WithDatabase(db))
	createSite := httptest.NewRecorder()
	server.Handler().ServeHTTP(createSite, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(fmt.Sprintf(`{"name":"t135","domains":["t135.local"],"upstream":%q,"status":"enabled","wafEnabled":false,"ccProtection":true,"semanticProtection":false,"policyMode":"standard"}`, upstream.URL))))
	if createSite.Code != http.StatusCreated {
		t.Fatalf("create site status=%d body=%s", createSite.Code, createSite.Body.String())
	}

	createChainPolicy := httptest.NewRecorder()
	server.Handler().ServeHTTP(createChainPolicy, httptest.NewRequest(http.MethodPost, "/api/cc-protection", strings.NewReader(`{"name":"ua action chain","scope":"ua","threshold":1,"windowSeconds":60,"action":"observe>captcha>temp-block>long-block","enabled":true}`)))
	if createChainPolicy.Code != http.StatusCreated {
		t.Fatalf("create action chain policy status=%d body=%s", createChainPolicy.Code, createChainPolicy.Body.String())
	}

	assertCCStatus(t, server, "/ua", "t135.local", "198.51.100.10:1001", "sqlmap/1.7", http.StatusOK)
	assertCCStatus(t, server, "/ua", "t135.local", "198.51.100.10:1002", "sqlmap/1.7", http.StatusOK)
	assertCCStatus(t, server, "/ua", "t135.local", "198.51.100.10:1003", "sqlmap/1.7", http.StatusFound)
	assertCCStatus(t, server, "/ua", "t135.local", "198.51.100.10:1004", "sqlmap/1.7", http.StatusForbidden)
	assertCCStatus(t, server, "/ua", "t135.local", "198.51.100.10:1005", "sqlmap/1.7", http.StatusForbidden)

	blocks := listCCBlocks(t, server)
	if blocks.Total == 0 {
		t.Fatalf("expected active cc block after temp-block escalation")
	}
	var blockedKey string
	for _, block := range blocks.Blocks {
		if block.SourceIP == "198.51.100.10" && block.PolicyName == "ua action chain" && block.Action == "temp-block" {
			blockedKey = block.Key
			break
		}
	}
	if blockedKey == "" {
		t.Fatalf("missing active block for ua action chain: %#v", blocks.Blocks)
	}
	unblock := httptest.NewRecorder()
	server.Handler().ServeHTTP(unblock, httptest.NewRequest(http.MethodDelete, "/api/protection/cc-blocks/"+url.PathEscape(blockedKey), nil))
	if unblock.Code != http.StatusOK {
		t.Fatalf("unblock key status=%d body=%s", unblock.Code, unblock.Body.String())
	}
	assertCCStatus(t, server, "/ua", "t135.local", "198.51.100.10:1007", "sqlmap/1.7", http.StatusOK)
	assertCCStatus(t, server, "/ua", "t135.local", "198.51.100.11:1006", "curl/8", http.StatusOK)

	create404Policy := httptest.NewRecorder()
	server.Handler().ServeHTTP(create404Policy, httptest.NewRequest(http.MethodPost, "/api/cc-protection", strings.NewReader(`{"name":"404 scanner","scope":"404","threshold":1,"windowSeconds":60,"action":"block","enabled":true}`)))
	if create404Policy.Code != http.StatusCreated {
		t.Fatalf("create 404 policy status=%d body=%s", create404Policy.Code, create404Policy.Body.String())
	}
	assertCCStatus(t, server, "/missing-a", "t135.local", "198.51.100.20:2001", "browser", http.StatusNotFound)
	assertCCStatus(t, server, "/missing-b", "t135.local", "198.51.100.20:2002", "browser", http.StatusForbidden)

	createLoginPolicy := httptest.NewRecorder()
	server.Handler().ServeHTTP(createLoginPolicy, httptest.NewRequest(http.MethodPost, "/api/cc-protection", strings.NewReader(`{"name":"login brute force","scope":"login-failure:/login","threshold":1,"windowSeconds":60,"action":"captcha","enabled":true}`)))
	if createLoginPolicy.Code != http.StatusCreated {
		t.Fatalf("create login policy status=%d body=%s", createLoginPolicy.Code, createLoginPolicy.Body.String())
	}
	assertCCStatus(t, server, "/login", "t135.local", "198.51.100.30:3001", "browser", http.StatusUnauthorized)
	assertCCStatus(t, server, "/login", "t135.local", "198.51.100.30:3002", "browser", http.StatusFound)

	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	var policies []database.CCPolicy
	if err := db.Where("name IN ?", []string{"ua action chain", "404 scanner", "login brute force"}).Order("id asc").Find(&policies).Error; err != nil {
		t.Fatalf("query policies: %v", err)
	}
	if len(policies) != 3 || policies[0].Action != "observe>captcha>temp-block>long-block" {
		t.Fatalf("cc policies not persisted with action chain: %#v", policies)
	}

	var attacks []database.AttackLog
	if err := db.Where("site_name = ? AND stage = ?", "t135", "cc").Order("id asc").Find(&attacks).Error; err != nil {
		t.Fatalf("query cc attacks: %v", err)
	}
	if !hasCCAttack(attacks, "cc", "observe", "scope=ua", "sqlmap/1.7") || !hasCCAttack(attacks, "cc", "block", "temp-block", "sqlmap/1.7") {
		t.Fatalf("missing ua cc explain logs: %#v", attacks)
	}
	if !hasCCAttack(attacks, "scanner-404", "block", "404 scanner", "404") {
		t.Fatalf("missing 404 scanner explain log: %#v", attacks)
	}
	if !hasCCAttack(attacks, "login-bruteforce", "block", "login-failure:/login", "captcha") {
		t.Fatalf("missing login failure captcha explain log: %#v", attacks)
	}
}

func listCCBlocks(t *testing.T, server *Server) ccBlockResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/protection/cc-blocks", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list cc blocks status=%d body=%s", rec.Code, rec.Body.String())
	}
	var blocks ccBlockResponse
	if err := json.NewDecoder(rec.Body).Decode(&blocks); err != nil {
		t.Fatalf("decode cc blocks: %v", err)
	}
	return blocks
}

func assertCCStatus(t *testing.T, server *Server, path, host, remoteAddr, ua string, want int) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", ua)
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s ua=%s status=%d want=%d body=%s", host, path, ua, rec.Code, want, rec.Body.String())
	}
}

func hasCCAttack(attacks []database.AttackLog, attackType, action string, needles ...string) bool {
	for _, attack := range attacks {
		if attack.AttackType != attackType || attack.Action != action {
			continue
		}
		haystack := attack.RuleMessage + " " + attack.PayloadSnippet + " " + attack.RuleID
		matched := true
		for _, needle := range needles {
			if !strings.Contains(haystack, needle) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

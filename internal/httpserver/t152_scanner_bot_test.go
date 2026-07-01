package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"

	"gorm.io/gorm"
)

type scannerBotTrendResponse struct {
	Trend []struct {
		Time     string `json:"time"`
		Requests int    `json:"requests"`
		Blocked  int    `json:"blocked"`
	} `json:"trend"`
	Total int `json:"total"`
}

type scannerBotRankResponse struct {
	Items []trafficRankItem `json:"items"`
	Total int               `json:"total"`
}

func TestT152ScannerDetectionAndAPIs(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env", "/wp-admin/install.php":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer upstream.Close()

	detectionEngine, err := detection.NewManager("../../rules", nil, nil, false)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 4096}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	createSite(t, server, "t152", "t152.local", upstream.URL, 5)

	assertWAFStatusWithUA(t, server, http.MethodGet, "/", "t152.local", "198.51.100.152:1001", "", "sqlmap/1.8", http.StatusForbidden, "sqlmap user-agent should be blocked as scanner")
	assertWAFStatusWithUA(t, server, http.MethodGet, "/probe", "t152.local", "198.51.100.153:1002", "", "nuclei - Open-source project", http.StatusForbidden, "nuclei user-agent should be blocked as scanner")
	assertWAFStatusWithUA(t, server, http.MethodGet, "/check", "t152.local", "198.51.100.154:1003", "", "Nikto/2.5.0", http.StatusForbidden, "nikto user-agent should be blocked as scanner")
	assertWAFStatusWithUA(t, server, http.MethodGet, "/.env", "t152.local", "198.51.100.155:1004", "", "Mozilla/5.0", http.StatusForbidden, "scanner probe path should be recognized from typical path probing")

	enableSiteCC(t, server, 1, upstream.URL)
	createCCPolicy(t, server, `{"name":"scanner block","scope":"ua","threshold":1,"windowSeconds":60,"action":"temp-block","enabled":true}`)
	assertCCStatus(t, server, "/catalog", "t152.local", "198.51.100.200:2001", "dirsearch/0.4", http.StatusOK)
	assertCCStatus(t, server, "/catalog", "t152.local", "198.51.100.200:2002", "dirsearch/0.4", http.StatusForbidden)

	blocks := getJSON[ccBlockResponse](t, server, "/api/protection/cc-blocks")
	if blocks.Total != 1 || len(blocks.Blocks) != 1 {
		t.Fatalf("expected one active cc block, got %#v", blocks)
	}
	block := blocks.Blocks[0]
	if block.SourceIP != "198.51.100.200" || block.PolicyName != "scanner block" || block.Scope != "ua" {
		t.Fatalf("unexpected active block identity: %#v", block)
	}
	if block.BlockUntil == "" || block.RemainingSeconds <= 0 || block.RecentPath != "/catalog" || !strings.Contains(block.UserAgent, "dirsearch") {
		t.Fatalf("expected runtime metadata in active block entry, got %#v", block)
	}

	assertEventuallyT152AttackLogs(t, db, func(logs []database.AttackLog) bool {
		return hasAttackTypeWithNeedles(logs, "scanner", "sqlmap") &&
			hasAttackTypeWithNeedles(logs, "scanner", "nuclei") &&
			hasAttackTypeWithNeedles(logs, "scanner", "nikto") &&
			hasAttackTypeWithNeedles(logs, "scanner", "/.env")
	})

	filtered := getJSON[attackLogResponse](t, server, "/api/attack-logs?attackType=scanner")
	if filtered.Total < 4 {
		t.Fatalf("scanner filter should return scanner attack logs, got %#v", filtered)
	}

	ccEvents := getJSON[ccBotEventResponse](t, server, "/api/protection/cc-events?attackType=scanner")
	if ccEvents.Total == 0 {
		t.Fatalf("scanner cc/bot events should be returned from real logs")
	}

	trend := getJSON[scannerBotTrendResponse](t, server, "/api/protection/cc-events/trend?attackType=scanner")
	if trend.Total == 0 || len(trend.Trend) == 0 {
		t.Fatalf("scanner trend should aggregate from real logs: %#v", trend)
	}

	topIP := getJSON[scannerBotRankResponse](t, server, "/api/protection/cc-events/top-ip?attackType=scanner")
	if topIP.Total == 0 || topIP.Items[0].Key == "" {
		t.Fatalf("scanner top ip should be populated: %#v", topIP)
	}

	topUA := getJSON[scannerBotRankResponse](t, server, "/api/protection/cc-events/top-ua?attackType=scanner")
	if topUA.Total == 0 {
		t.Fatalf("scanner top ua should be populated from real data: %#v", topUA)
	}
	foundScannerUA := false
	for _, item := range topUA.Items {
		key := strings.ToLower(item.Key)
		if strings.Contains(key, "dirsearch") || strings.Contains(key, "sqlmap") {
			foundScannerUA = true
			break
		}
	}
	if !foundScannerUA {
		t.Fatalf("scanner top ua should include scanner signatures from real data: %#v", topUA)
	}

	topPath := getJSON[scannerBotRankResponse](t, server, "/api/protection/cc-events/top-path?attackType=scanner")
	if topPath.Total == 0 || topPath.Items[0].Key == "" {
		t.Fatalf("scanner top path should be populated: %#v", topPath)
	}

	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func createCCPolicy(t *testing.T, server *Server, payload string) {
	t.Helper()
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/cc-protection", strings.NewReader(payload)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cc policy status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func enableSiteCC(t *testing.T, server *Server, siteID uint, upstreamURL string) {
	t.Helper()
	rec := httptest.NewRecorder()
	payload := fmt.Sprintf(`{"name":"t152","domains":["t152.local"],"upstream":%q,"status":"enabled","wafEnabled":true,"ccProtection":true,"semanticProtection":true,"policyMode":"custom","blockScoreThreshold":5,"ruleGroups":["custom"]}`, upstreamURL)
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/sites/%d", siteID), strings.NewReader(payload)))
	if rec.Code != http.StatusOK {
		t.Fatalf("enable cc status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func assertWAFStatusWithUA(t *testing.T, server *Server, method, path, host, remoteAddr, body, ua string, want int, reason string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = host
	req.RemoteAddr = remoteAddr
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s: status=%d want=%d body=%s", reason, rec.Code, want, rec.Body.String())
	}
}

func assertEventuallyT152AttackLogs(t *testing.T, db *gorm.DB, check func([]database.AttackLog) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var logs []database.AttackLog
		if err := db.Order("id asc").Find(&logs).Error; err != nil {
			t.Fatalf("query attack logs: %v", err)
		}
		if check(logs) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	var logs []database.AttackLog
	if err := db.Order("id asc").Find(&logs).Error; err != nil {
		t.Fatalf("query attack logs: %v", err)
	}
	if !check(logs) {
		t.Fatalf("scanner attack logs missing expected entries: %#v", logs)
	}
}

func hasAttackTypeWithNeedles(logs []database.AttackLog, attackType string, needles ...string) bool {
	for _, log := range logs {
		if !strings.Contains(strings.ToLower(log.AttackType), strings.ToLower(attackType)) {
			continue
		}
		haystack := strings.ToLower(strings.Join([]string{
			log.SiteName,
			log.SourceIP,
			log.Method,
			log.Path,
			log.AttackType,
			log.Action,
			log.Stage,
			log.RuleID,
			log.RuleMessage,
			log.PayloadSnippet,
			log.ExplanationJSON,
			log.OperatorSuggestion,
		}, " "))
		matched := true
		for _, needle := range needles {
			if !strings.Contains(haystack, strings.ToLower(needle)) {
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

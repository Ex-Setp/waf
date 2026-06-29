package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

type validationCase struct {
	Name          string
	Method        string
	Path          string
	Body          string
	ContentType   string
	UserAgent     string
	ExpectedCode  int
	Attack        bool
	ExpectedRule  string
	FalsePositive bool
}

func TestT120RealWorldValidationSet(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "validation")
		if strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Content-Type", "text/css")
		}
		_, _ = io.WriteString(w, "origin:"+r.Method+":"+r.URL.RequestURI())
	}))
	defer upstream.Close()

	site := database.Site{Name: "t120", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: true, CCProtection: true, BlockScoreThreshold: 5}
	_ = site.SetDomains([]string{"test.local"})
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&database.CCPolicy{Name: "t120-login-cc", Scope: "/login", Threshold: 2, WindowSeconds: 60, Action: database.CCActionBlock, Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}

	rules, err := detection.NewManager("../../rules", nil, nil, false)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	processor := pipeline.New(pipeline.Config{FailOpen: false}, pipeline.WithDetection(rules))
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 2 << 20}, processor, WithDatabase(db))

	cases := []validationCase{
		{Name: "普通页面", Method: http.MethodGet, Path: "/", ExpectedCode: http.StatusOK},
		{Name: "登录接口", Method: http.MethodPost, Path: "/login", Body: "username=alice&password=safe", ContentType: "application/x-www-form-urlencoded", ExpectedCode: http.StatusOK},
		{Name: "搜索接口正常查询", Method: http.MethodGet, Path: "/search?q=phone", ExpectedCode: http.StatusOK},
		{Name: "JSON API", Method: http.MethodPost, Path: "/json-api/order", Body: `{"product":"book","count":1}`, ContentType: "application/json", ExpectedCode: http.StatusOK},
		{Name: "文件上传接口", Method: http.MethodPost, Path: "/upload", Body: multipartBody(t), ContentType: "multipart/form-data; boundary=t120boundary", ExpectedCode: http.StatusOK},
		{Name: "静态资源", Method: http.MethodGet, Path: "/static/app.css", ExpectedCode: http.StatusOK},
		{Name: "SQL 注入", Method: http.MethodGet, Path: "/search?q=" + url.QueryEscape("1 union select password from users"), ExpectedCode: http.StatusForbidden, Attack: true, ExpectedRule: "942100"},
		{Name: "XSS", Method: http.MethodGet, Path: "/search?q=" + url.QueryEscape("<script>alert(1)</script>"), ExpectedCode: http.StatusForbidden, Attack: true, ExpectedRule: "941100"},
		{Name: "路径遍历", Method: http.MethodGet, Path: "/download?file=" + url.QueryEscape("../../etc/passwd"), ExpectedCode: http.StatusForbidden, Attack: true, ExpectedRule: "930100"},
		{Name: "命令注入", Method: http.MethodGet, Path: "/ping?host=" + url.QueryEscape("127.0.0.1;cat /etc/passwd"), ExpectedCode: http.StatusForbidden, Attack: true, ExpectedRule: "932100"},
		{Name: "恶意 User-Agent", Method: http.MethodGet, Path: "/", UserAgent: "sqlmap/1.8", ExpectedCode: http.StatusForbidden, Attack: true, ExpectedRule: "913100"},
		{Name: "编码绕过 payload", Method: http.MethodGet, Path: "/search?q=un%2520ion%2520sel%2520ect", ExpectedCode: http.StatusForbidden, Attack: true, ExpectedRule: "942100"},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.Method, tc.Path, strings.NewReader(tc.Body))
			req.Host = "test.local"
			req.RemoteAddr = "192.0.2.20:1234"
			if tc.ContentType != "" {
				req.Header.Set("Content-Type", tc.ContentType)
			}
			if tc.UserAgent != "" {
				req.Header.Set("User-Agent", tc.UserAgent)
			} else {
				req.Header.Set("User-Agent", "Mozilla/5.0 T120")
			}
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.ExpectedCode {
				t.Fatalf("expected %d got %d body=%s", tc.ExpectedCode, rec.Code, rec.Body.String())
			}
			if !tc.Attack && !strings.Contains(rec.Body.String(), "origin:") {
				t.Fatalf("normal request did not reach upstream: %s", rec.Body.String())
			}
		})
	}

	// 高频请求 / CC：前两次允许，第三次命中站点级 CC 策略。
	for i := 1; i <= 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.Host = "test.local"
		req.RemoteAddr = "198.51.100.77:4321"
		server.Handler().ServeHTTP(rec, req)
		if i < 3 && rec.Code != http.StatusOK {
			t.Fatalf("cc warmup %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
		if i == 3 && rec.Code != http.StatusForbidden {
			t.Fatalf("cc block status=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	report := buildT120Report(t, server, len(cases)+3)
	assertT120Logs(t, report, cases)
}

func multipartBody(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	mw := multipart.NewWriter(&b)
	if err := mw.SetBoundary("t120boundary"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("hello"))
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

type t120Report struct {
	Access accessLogResponse
	Attack attackLogResponse
	Dash   dashboardOverview
}

func buildT120Report(t *testing.T, server *Server, expectedRequests int) t120Report {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var report t120Report
	for time.Now().Before(deadline) {
		accessRec := httptest.NewRecorder()
		server.Handler().ServeHTTP(accessRec, httptest.NewRequest(http.MethodGet, "/api/access-logs?site=t120&page=1&pageSize=200", nil))
		if err := json.Unmarshal(accessRec.Body.Bytes(), &report.Access); err != nil {
			t.Fatal(err)
		}
		attackRec := httptest.NewRecorder()
		server.Handler().ServeHTTP(attackRec, httptest.NewRequest(http.MethodGet, "/api/attack-logs?site=t120&page=1&pageSize=200", nil))
		if err := json.Unmarshal(attackRec.Body.Bytes(), &report.Attack); err != nil {
			t.Fatal(err)
		}
		dashRec := httptest.NewRecorder()
		server.Handler().ServeHTTP(dashRec, httptest.NewRequest(http.MethodGet, "/api/dashboard/overview", nil))
		if err := json.Unmarshal(dashRec.Body.Bytes(), &report.Dash); err != nil {
			t.Fatal(err)
		}
		if report.Access.Total >= expectedRequests && report.Attack.Total >= 7 {
			return report
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("logs not complete: access=%d attack=%d", report.Access.Total, report.Attack.Total)
	return report
}

func assertT120Logs(t *testing.T, report t120Report, cases []validationCase) {
	t.Helper()
	rows := make([]string, 0, len(cases)+1)
	rows = append(rows, "| 类型 | Payload | 预期 | 实际 | 是否误报 | 日志是否完整 | 后续动作 |")
	rows = append(rows, "| --- | --- | --- | --- | --- | --- | --- |")
	for _, tc := range cases {
		actual := fmt.Sprintf("HTTP %d", tc.ExpectedCode)
		logComplete := hasAccessLog(report.Access.Logs, tc.Path, tc.ExpectedCode)
		if tc.Attack {
			logComplete = logComplete && hasAttackRule(report.Attack.Logs, tc.ExpectedRule)
		}
		if !logComplete {
			t.Fatalf("missing complete logs for %s: access=%#v attack=%#v", tc.Name, report.Access.Logs, report.Attack.Logs)
		}
		rows = append(rows, fmt.Sprintf("| %s | `%s` | HTTP %d | %s | %t | %t | 已通过自动验证 |", tc.Name, strings.ReplaceAll(tc.Path, "|", "\\|"), tc.ExpectedCode, actual, tc.FalsePositive, logComplete))
	}
	if report.Dash.Metrics[0].Value <= 0 || report.Dash.Metrics[1].Value <= 0 {
		t.Fatalf("dashboard metrics not updated: %#v", report.Dash.Metrics)
	}
	t.Log("T120 validation report:\n" + strings.Join(rows, "\n"))
}

func hasAccessLog(logs []accessLogEntry, path string, status int) bool {
	needle := strings.Split(path, "?")[0]
	for _, log := range logs {
		if log.Status == status && (log.Path == needle || strings.HasPrefix(path, log.Path)) {
			return true
		}
	}
	return false
}

func hasAttackRule(logs []attackLogEntry, ruleID string) bool {
	for _, log := range logs {
		if log.RuleID == ruleID || log.Stage == "cc" && ruleID == "" {
			return true
		}
	}
	return false
}

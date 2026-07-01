package httpserver

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
)

func TestT153UploadMetadataFeedsDetectionArgs(t *testing.T) {
	processor := &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 8192}, processor)

	body, contentType := multipartUploadBody(t, "upload", "..\\..\\shell.jpg.php", "image/jpeg", []byte(phpProbeGet()))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	if len(processor.calls) != 1 {
		t.Fatalf("processor calls=%d want 1", len(processor.calls))
	}
	args := processor.calls[0].Args
	if firstArg(args, "upload") != "shell.jpg.php" {
		t.Fatalf("upload arg=%q want shell.jpg.php; args=%#v", firstArg(args, "upload"), args)
	}
	if firstArg(args, "upload.filename") != "shell.jpg.php" || firstArg(args, "upload.extension") != ".php" {
		t.Fatalf("missing filename/extension metadata: %#v", args)
	}
	if firstArg(args, "upload.content_type") != "image/jpeg" || firstArg(args, "upload.magic") != "php" {
		t.Fatalf("missing content-type/magic metadata: %#v", args)
	}
	if !containsArgValue(args, "upload.risk", "path_traversal") || !containsArgValue(args, "upload.risk", "double_extension") || !containsArgValue(args, "upload.risk", "webshell_code") {
		t.Fatalf("missing upload risk metadata: %#v", args)
	}
	if snippet := firstArg(args, "upload.snippet"); !strings.Contains(snippet, "<?"+"php") {
		t.Fatalf("snippet=%q want php snippet", snippet)
	}
	if strings.Contains(firstArg(args, "upload.snippet"), "cmd']); ?>") && len(firstArg(args, "upload.snippet")) > 512 {
		t.Fatalf("snippet not capped: %q", firstArg(args, "upload.snippet"))
	}
}

func TestT153UploadWebshellAndTraversalClosure(t *testing.T) {
	db := testDB(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	ruleDir := t.TempDir()
	ruleBytes, err := os.ReadFile(filepath.Join("..", "..", "rules", "REQUEST-907-UPLOAD-WEBSHELL.conf"))
	if err != nil {
		t.Fatalf("read 907 rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ruleDir, "REQUEST-907-UPLOAD-WEBSHELL.conf"), ruleBytes, 0o600); err != nil {
		t.Fatalf("write 907 rules: %v", err)
	}
	detectionEngine, err := detection.NewManager(ruleDir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	semanticEngine := detection.NewSemanticEngine(nil, detection.SemanticOptions{})
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine), pipeline.WithSemantic(semanticEngine))
	server := New(config.ServerConfig{Mode: "debug"}, config.SecurityConfig{MaxBodySize: 16384, EnableSemantic: true}, processor, WithDatabase(db), WithDetectionEngine(detectionEngine))

	site := database.Site{Name: "t153", Upstream: upstream.URL, Status: database.SiteStatusEnabled, WAFEnabled: true, SemanticProtection: true, PolicyMode: database.PolicyModeStrict, BlockScoreThreshold: 5}
	if err := site.SetDomains([]string{"t153.local"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	server.reloadRuntime(httptest.NewRequest(http.MethodGet, "/", nil))

	tests := []struct {
		name          string
		filename      string
		contentType   string
		content       []byte
		wantRuleID    string
		wantAttack    string
		wantEvidence  []string
		wantLogAbsent []string
	}{
		{
			name:          "double extension php webshell",
			filename:      "avatar.jpg.php",
			contentType:   "image/jpeg",
			content:       []byte(phpProbePost()),
			wantRuleID:    "907003",
			wantAttack:    "upload",
			wantEvidence:  []string{"double_extension", "webshell_code", "avatar.jpg.php"},
			wantLogAbsent: []string{"$_POST['cmd']); ?>"},
		},
		{
			name:          "path traversal filename",
			filename:      "../../cmd.jsp",
			contentType:   "application/octet-stream",
			content:       []byte(jspProbe()),
			wantRuleID:    "907002",
			wantAttack:    "upload",
			wantEvidence:  []string{"path_traversal", "Runtime.getRuntime().exec", "cmd.jsp"},
			wantLogAbsent: []string{"../../cmd.jsp"},
		},
		{
			name:          "aspx webshell executable upload",
			filename:      "shell.aspx",
			contentType:   "text/plain",
			content:       []byte("<script runat=\"server\">Response.Write(eval(Request.Form[\"cmd\"]));</script>"),
			wantRuleID:    "907003",
			wantAttack:    "upload",
			wantEvidence:  []string{"executable_extension", "shell.aspx", "aspx"},
			wantLogAbsent: nil,
		},
		{
			name:          "content type mismatch pdf disguised as png",
			filename:      "report.png",
			contentType:   "image/png",
			content:       []byte("%PDF-1.5 report"),
			wantRuleID:    "907005",
			wantAttack:    "upload",
			wantEvidence:  []string{"content_type_mismatch", "FILES:upload.magic", "\"pdf\""},
			wantLogAbsent: []string{"%PDF-1.5 report"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, reqContentType := multipartUploadBody(t, "upload", tc.filename, tc.contentType, tc.content)
			req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
			req.Host = "t153.local"
			req.RemoteAddr = "192.0.2.153:1001"
			req.Header.Set("Content-Type", reqContentType)
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d want 403 body=%s", rec.Code, rec.Body.String())
			}
			flushAudit(t, server)
			var log database.AttackLog
			if err := db.Order("created_at desc, id desc").First(&log).Error; err != nil {
				t.Fatalf("load attack log: %v", err)
			}
			if log.RuleID != tc.wantRuleID || log.AttackType != tc.wantAttack {
				t.Fatalf("unexpected attack log: %#v", log)
			}
			for _, want := range tc.wantEvidence {
				if !strings.Contains(log.ExplanationJSON, want) && !strings.Contains(log.PayloadSnippet, want) && !strings.Contains(log.RuleMessage, want) {
					t.Fatalf("missing evidence %q in log:\nrule=%s\nexplanation=%s\nsnippet=%s", want, log.RuleMessage, log.ExplanationJSON, log.PayloadSnippet)
				}
			}
			for _, unwanted := range tc.wantLogAbsent {
				if strings.Contains(log.ExplanationJSON, unwanted) || strings.Contains(log.PayloadSnippet, unwanted) {
					t.Fatalf("unexpected full body/path leak %q:\nexplanation=%s\nsnippet=%s", unwanted, log.ExplanationJSON, log.PayloadSnippet)
				}
			}
		})
	}
}

func TestT153BenignUploadsPassIncludingOctetStream(t *testing.T) {
	ruleDir := t.TempDir()
	ruleBytes, err := os.ReadFile(filepath.Join("..", "..", "rules", "REQUEST-907-UPLOAD-WEBSHELL.conf"))
	if err != nil {
		t.Fatalf("read 907 rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ruleDir, "REQUEST-907-UPLOAD-WEBSHELL.conf"), ruleBytes, 0o600); err != nil {
		t.Fatalf("write 907 rules: %v", err)
	}
	detectionEngine, err := detection.NewManager(ruleDir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	semanticEngine := detection.NewSemanticEngine(nil, detection.SemanticOptions{})
	processor := pipeline.New(pipeline.Config{}, pipeline.WithDetection(detectionEngine), pipeline.WithSemantic(semanticEngine))

	tests := []struct {
		name        string
		filename    string
		contentType string
		content     []byte
	}{
		{name: "jpeg", filename: "photo.jpg", contentType: "image/jpeg", content: []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F'}},
		{name: "docx octet stream", filename: "report.docx", contentType: "application/octet-stream", content: []byte("PK\x03\x04docx payload")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := processor.Process(context.Background(), pipeline.Request{
				ID:      "req-t153-benign",
				Method:  http.MethodPost,
				Path:    "/upload",
				Headers: http.Header{"Content-Type": {"multipart/form-data; boundary=test"}},
				Args:    mustMultipartArgs(t, tc.filename, tc.contentType, tc.content),
			})
			if err != nil {
				t.Fatalf("Process: %v", err)
			}
			if result.Decision == pipeline.DecisionBlock {
				t.Fatalf("benign upload blocked: %+v", result)
			}
		})
	}
}

func multipartUploadBody(t *testing.T, fieldName, filename, contentType string, content []byte) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="`+fieldName+`"; filename="`+filename+`"`)
	if strings.TrimSpace(contentType) != "" {
		header.Set("Content-Type", contentType)
	}
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("Write multipart content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close multipart writer: %v", err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func containsArgValue(args map[string][]string, key, want string) bool {
	for _, value := range args[key] {
		if value == want {
			return true
		}
	}
	return false
}

func mustMultipartArgs(t *testing.T, filename, contentType string, content []byte) map[string][]string {
	t.Helper()
	body, reqContentType := multipartUploadBody(t, "upload", filename, contentType, content)
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", reqContentType)
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 16384}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}})
	pipeReq, err := server.toPipelineRequest(req)
	if err != nil {
		t.Fatalf("toPipelineRequest: %v", err)
	}
	return pipeReq.Args
}

func phpProbeGet() string {
	return "<?" + "php " + "echo " + "shell" + "_exec($_GE" + "T['cmd']); ?>"
}

func phpProbePost() string {
	return "<?" + "php " + "echo " + "shell" + "_exec($_PO" + "ST['cmd']); ?>"
}

func jspProbe() string {
	return `<%@ page import="java.io.*" %><% Runtime.get` + `Runtime().ex` + `ec(request.getParameter("cmd")); %>`
}

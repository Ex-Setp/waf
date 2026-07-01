package detection

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aegis-waf/internal/requestparser"
)

func TestManagerLoadsRulesAndBlocksMatchingRequest(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "REQUEST-942.conf"), `
# CRS style SQLi rule
SecRule ARGS "@contains union select" "id:942100,phase:2,deny,status:403,msg:'SQL injection attempt'"
`)

	manager, err := NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	result, err := manager.Inspect(context.Background(), Request{URI: "/search?q=union select password"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected block decision, got %q", result.Decision)
	}
	if len(result.Matches) != 1 || result.Matches[0].ID != 942100 {
		t.Fatalf("unexpected matches: %+v", result.Matches)
	}
	if result.Score != 7 || result.Severity != "high" || result.Matches[0].Score != 7 || result.Matches[0].Severity != "high" {
		t.Fatalf("expected default high severity score, got result=%+v match=%+v", result, result.Matches[0])
	}
}

func TestManagerParsesRuleSeverityAndScore(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "scored.conf"), `SecRule ARGS "@contains probe" "id:100100,phase:2,deny,severity:'low',score:3,msg:'low confidence probe'"`)

	manager, err := NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	result, err := manager.Inspect(context.Background(), Request{URI: "/?q=probe"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Score != 3 || result.Severity != "low" {
		t.Fatalf("expected score=3 severity=low, got %+v", result)
	}
	if len(result.Matches) != 1 || result.Matches[0].Score != 3 || result.Matches[0].Severity != "low" {
		t.Fatalf("unexpected scored match: %+v", result.Matches)
	}
}

func TestManagerFiltersRulesByEnabledRuleGroups(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "REQUEST-942-SQLI.conf"), `SecRule ARGS "@contains union select" "id:942100,phase:2,deny,severity:'high',score:7,group:'sqli',msg:'SQL injection attempt'"`)
	writeRule(t, filepath.Join(dir, "REQUEST-941-XSS.conf"), `SecRule ARGS "@contains <script>" "id:941100,phase:2,deny,severity:'high',score:7,group:'xss',msg:'XSS attempt'"`)

	manager, err := NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	result, err := manager.Inspect(context.Background(), Request{URI: "/?q=union select <script>", EnabledRuleGroups: map[string]bool{"xss": true}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock || len(result.Matches) != 1 || result.Matches[0].ID != 941100 || result.Matches[0].Group != "xss" {
		t.Fatalf("expected only xss group to match, got %+v", result)
	}

	result, err = manager.Inspect(context.Background(), Request{URI: "/?q=union select <script>"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if len(result.Matches) != 2 || result.Score != 14 {
		t.Fatalf("expected empty group filter to keep all rules, got %+v", result)
	}
}

func TestManagerSupportsCustomFilesAndDisabledRuleIDs(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(t.TempDir(), "custom.conf")
	writeRule(t, custom, `SecRule REQUEST_URI "@contains /admin" "id:100001,phase:2,deny,msg:'admin probe'"`)

	manager, err := NewManager(dir, []string{custom}, []int{100001}, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	result, err := manager.Inspect(context.Background(), Request{URI: "/admin"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Fatalf("expected disabled rule to allow, got %q", result.Decision)
	}
	if err := manager.EnableRule(100001); err != nil {
		t.Fatalf("EnableRule returned error: %v", err)
	}
	result, err = manager.Inspect(context.Background(), Request{URI: "/admin"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected enabled rule to block, got %q", result.Decision)
	}
}

func TestReloadIsAtomicOnInvalidRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local.conf")
	writeRule(t, path, `SecRule REQUEST_URI "@contains bad" "id:1,phase:2,deny,msg:'bad uri'"`)
	manager, err := NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	writeRule(t, path, `SecRule REQUEST_URI "@contains broken"`)
	if err := manager.Reload(context.Background()); err == nil {
		t.Fatal("expected invalid reload error")
	}
	result, err := manager.Inspect(context.Background(), Request{URI: "/bad"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected previous ruleset to remain active, got %q", result.Decision)
	}
}

func TestWatcherReloadsOnRuleWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local.conf")
	writeRule(t, path, `SecRule REQUEST_URI "@contains before" "id:1,phase:2,deny,msg:'before'"`)
	manager, err := NewManager(dir, nil, nil, true)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	reloaded := make(chan struct{}, 1)
	watcher, err := NewWatcher(manager, func() { reloaded <- struct{}{} }, func(err error) { t.Log(err) })
	if err != nil {
		t.Fatalf("NewWatcher returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	writeRule(t, path, `SecRule REQUEST_URI "@contains after" "id:2,phase:2,deny,msg:'after'"`)
	select {
	case <-reloaded:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for reload")
	}
	result, err := manager.Inspect(context.Background(), Request{URI: "/after"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected reloaded rule to block, got %q", result.Decision)
	}
}

func TestManagerMatchesParsedVariablesAndCapturesEvidence(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "local.conf"), `
SecRule JSON:role "@streq admin" "id:910034,phase:2,deny,severity:'critical',score:10,msg:'role tamper'"
SecRule GRAPHQL:depth "@gt 12" "id:910008,phase:2,deny,severity:'critical',score:10,msg:'graphql depth'"
SecRule JWT:header.alg "@streq none" "id:910030,phase:1,deny,severity:'high',score:7,msg:'jwt none'"
SecRule META:request.content_length.count "@gt 1" "id:909048,phase:1,deny,severity:'critical',score:10,msg:'duplicate content-length'"
`)

	manager, err := NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	parsed := requestparser.Parse("POST", "/graphql", map[string][]string{
		"Content-Type":      {"application/json"},
		"Content-Length":    {"52", "52"},
		"Authorization":     {"Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
		"Transfer-Encoding": {"chunked"},
	}, []byte(`{"query":"{a{b{c{d{e{f{g{h{i{j{k{l{m}}}}}}}}}}}}","role":"admin"}`), requestparser.Options{})
	req := Request{
		Method:        "POST",
		URI:           "/graphql",
		Headers:       map[string][]string{"Content-Type": {"application/json"}, "Content-Length": {"52", "52"}, "Authorization": {"Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."}},
		Body:          `{"query":"{a{b{c{d{e{f{g{h{i{j{k{l{m}}}}}}}}}}}}","role":"admin"}`,
		ParsedRequest: parsed,
	}
	result, err := manager.Inspect(context.Background(), req)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected block decision, got %+v", result)
	}
	if len(result.Matches) < 4 {
		t.Fatalf("expected 4 matches, got %+v", result.Matches)
	}
	assertEvidenceContains(t, result.Matches, 910034, "JSON:role=admin")
	assertEvidenceContains(t, result.Matches, 910008, "GRAPHQL:depth=13")
	assertEvidenceContains(t, result.Matches, 910030, "JWT:header.alg=none")
	assertEvidenceContains(t, result.Matches, 909048, "META:request.content_length.count=2")
}

func TestManagerRegexDoesNotLowercaseRequestMethod(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "protocol.conf"), `SecRule REQUEST_METHOD "@rx ^(get|post|put|delete|patch)$" "id:909024,phase:1,log,severity:'info',msg:'case-obfuscated method'"`)

	manager, err := NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	allowed, err := manager.Inspect(context.Background(), Request{Method: "GET"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if len(allowed.Matches) != 0 {
		t.Fatalf("uppercase GET should not match lowercase-only regex, got %+v", allowed.Matches)
	}

	matched, err := manager.Inspect(context.Background(), Request{Method: "get"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if len(matched.Matches) != 1 || matched.Matches[0].ID != 909024 {
		t.Fatalf("lowercase get should match, got %+v", matched.Matches)
	}
}

func TestManagerMatchesHeaderNameRegexPerHeader(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "protocol.conf"), `SecRule REQUEST_HEADERS_NAMES "@rx [^a-zA-Z0-9\-_]" "id:909043,phase:1,deny,severity:'warning',msg:'invalid header name'"`)

	manager, err := NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	allowed, err := manager.Inspect(context.Background(), Request{Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}, "Content-Type": {"application/json"}}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if len(allowed.Matches) != 0 {
		t.Fatalf("valid canonical headers should not match, got %+v", allowed.Matches)
	}

	blocked, err := manager.Inspect(context.Background(), Request{Headers: map[string][]string{"Bad:Name": {"x"}}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if len(blocked.Matches) != 1 || blocked.Matches[0].ID != 909043 {
		t.Fatalf("invalid header name should match, got %+v", blocked.Matches)
	}
	assertEvidenceContains(t, blocked.Matches, 909043, "REQUEST_HEADERS_NAMES=Bad:Name")
}

func writeRule(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir rule dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
}

func assertEvidenceContains(t *testing.T, matches []MatchedRule, id int, want string) {
	t.Helper()
	for _, match := range matches {
		if match.ID != id {
			continue
		}
		for _, evidence := range match.Evidence {
			if evidence == want {
				return
			}
		}
		t.Fatalf("match %d evidence=%v, want %q", id, match.Evidence, want)
	}
	t.Fatalf("match %d not found in %+v", id, matches)
}

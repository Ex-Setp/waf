package detection

import (
	"context"
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

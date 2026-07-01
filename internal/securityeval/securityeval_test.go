package securityeval

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestT149SecurityCoverage(t *testing.T) {
	result, err := Evaluate(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("coverage gate failed: %v\nmissed=%+v\nfalsePositives=%+v", err, result.MissedAttacks, result.FalsePositives)
	}
	if result.AttackTotal < 30 || result.BenignTotal < 10 {
		t.Fatalf("corpus too small for T149 baseline: attacks=%d benign=%d", result.AttackTotal, result.BenignTotal)
	}
	for _, category := range []string{"api", "bot", "protocol", "rce", "scanner", "sqli", "ssrf", "traversal", "upload", "xss", "xxe"} {
		bucket := result.Category[category]
		if bucket.AttackTotal == 0 {
			t.Fatalf("missing attack samples for category %s", category)
		}
	}
}

func TestRulePackLoadsAndReportsT149Categories(t *testing.T) {
	result, err := Evaluate(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if result.RuleFileCount < 12 {
		t.Fatalf("expected seed plus T149 rule packs, got %d files", result.RuleFileCount)
	}
	if result.RuleCount < 60 {
		t.Fatalf("expected expanded T149 rule count, got %d", result.RuleCount)
	}
	markdown := result.Markdown()
	for _, text := range []string{"Attack block rate", "Benign false positives", "Category Coverage", "Top Missed Attack Samples", "Top False Positives", "sqli", "xss", "bot"} {
		if !strings.Contains(markdown, text) {
			t.Fatalf("coverage markdown missing %q:\n%s", text, markdown)
		}
	}
}

func TestSecurityCoverageBaselineRoundTripAndComparison(t *testing.T) {
	current := Result{
		AttackTotal:          10,
		AttackBlocked:        9,
		AttackBlockRate:      0.9,
		BenignTotal:          10,
		BenignFalsePositives: 1,
		BenignFalseRate:      0.1,
		RuleCount:            12,
		RuleVersion:          "current",
		Category: map[string]Bucket{
			"sqli": {AttackTotal: 2, AttackBlocked: 2, AttackBlockRate: 1, BenignTotal: 1, BenignFalsePositives: 0},
		},
		Thresholds: EvaluationGate{
			AttackBlockRate:      0.8,
			BenignFalsePositives: 2,
			MaxBlockRateDrop:     0.02,
			MaxFalsePositiveRise: 0,
		},
	}
	baseline := current
	baseline.AttackBlocked = 10
	baseline.AttackBlockRate = 1
	baseline.BenignFalsePositives = 0
	baseline.BenignFalseRate = 0
	baseline.RuleVersion = "baseline"
	raw, err := baseline.JSON()
	if err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}
	parsed, err := ParseBaseline(raw)
	if err != nil {
		t.Fatalf("ParseBaseline returned error: %v", err)
	}
	comparison := CompareResults(current, &parsed)
	if comparison.Gate.Passed {
		t.Fatalf("expected regression gate failure: %+v", comparison)
	}
	if comparison.AttackBlockDelta >= 0 {
		t.Fatalf("expected attack delta to be negative: %+v", comparison)
	}
	if comparison.BenignFalseDelta <= 0 {
		t.Fatalf("expected benign false positive delta to increase: %+v", comparison)
	}
	if err := current.ValidateWithBaseline(&parsed); err == nil {
		t.Fatalf("expected ValidateWithBaseline to fail")
	}
	markdown := current.MarkdownWithBaseline(&parsed)
	for _, text := range []string{"Baseline Comparison", "Gate Failures", "Attack block rate delta vs baseline"} {
		if !strings.Contains(markdown, text) {
			t.Fatalf("expected markdown to include %q", text)
		}
	}
}

func TestParseBaselineSupportsDirectResultJSON(t *testing.T) {
	input := Result{
		AttackTotal:          10,
		AttackBlocked:        9,
		AttackBlockRate:      0.9,
		BenignTotal:          10,
		BenignFalsePositives: 1,
		BenignFalseRate:      0.1,
		Thresholds:           EvaluationGate{},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	parsed, err := ParseBaseline(raw)
	if err != nil {
		t.Fatalf("ParseBaseline returned error: %v", err)
	}
	if parsed.Thresholds.AttackBlockRate != DefaultAttackBlockRateThreshold {
		t.Fatalf("expected default attack threshold, got %+v", parsed.Thresholds)
	}
	if parsed.Thresholds.BenignFalsePositives != DefaultBenignFalsePositiveLimit {
		t.Fatalf("expected default benign false positive threshold, got %+v", parsed.Thresholds)
	}
}

func TestValidateWithBaselineAllowsConfigurableRegressionThresholds(t *testing.T) {
	current := Result{
		AttackTotal:          10,
		AttackBlocked:        9,
		AttackBlockRate:      0.9,
		BenignTotal:          10,
		BenignFalsePositives: 1,
		BenignFalseRate:      0.1,
		Thresholds: EvaluationGate{
			AttackBlockRate:      0.8,
			BenignFalsePositives: 2,
			MaxBlockRateDrop:     0.2,
			MaxFalsePositiveRise: 1,
		},
	}
	baseline := Result{
		AttackTotal:          10,
		AttackBlocked:        10,
		AttackBlockRate:      1,
		BenignTotal:          10,
		BenignFalsePositives: 0,
		BenignFalseRate:      0,
	}
	if err := current.ValidateWithBaseline(&baseline); err != nil {
		t.Fatalf("expected configurable thresholds to allow current result: %v", err)
	}
	current.Thresholds.MaxBlockRateDrop = 0.05
	current.Thresholds.MaxFalsePositiveRise = 0
	if err := current.ValidateWithBaseline(&baseline); err == nil {
		t.Fatalf("expected regression thresholds to fail")
	}
}

func TestSecurityCoverageReportDocumentIsCurrentEnough(t *testing.T) {
	root, err := projectRoot()
	if err != nil {
		t.Fatalf("projectRoot returned error: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "docs", "security-coverage-report.md"))
	if err != nil {
		t.Fatalf("read coverage report: %v", err)
	}
	text := string(content)
	for _, expected := range []string{
		"Attack block rate",
		"Benign false positives",
		"Generated: 2026-06-30",
		"Rule files:",
		"Top Missed Attack Samples",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("security coverage report missing %q", expected)
		}
	}
}

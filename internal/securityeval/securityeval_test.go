package securityeval

import (
	"context"
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
	for _, text := range []string{"Attack block rate", "Benign false positives", "Category Coverage", "sqli", "xss", "bot"} {
		if !strings.Contains(markdown, text) {
			t.Fatalf("coverage markdown missing %q:\n%s", text, markdown)
		}
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
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("security coverage report missing %q", expected)
		}
	}
}

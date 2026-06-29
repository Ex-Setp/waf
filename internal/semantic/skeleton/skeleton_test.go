package skeleton

import (
	"strings"
	"testing"
)

func TestParseSQLExtractsSkeleton(t *testing.T) {
	skeleton, err := ParseSQL("SELECT id FROM users WHERE id=1 UNION SELECT username FROM admins")
	if err != nil {
		t.Fatalf("ParseSQL returned error: %v", err)
	}
	if skeleton.Language != LanguageSQL {
		t.Fatalf("expected SQL language, got %q", skeleton.Language)
	}
	if skeleton.Hash == "" || skeleton.Structure == "" || len(skeleton.NodeTypes) == 0 {
		t.Fatalf("expected populated skeleton: %+v", skeleton)
	}
	if !contains(skeleton.NodeTypes, "union") || !strings.Contains(skeleton.Structure, "clause:where") {
		t.Fatalf("expected union and where structure, got %+v", skeleton)
	}
}

func TestParseJSExtractsSkeleton(t *testing.T) {
	skeleton, err := ParseJS("eval(document.cookie)")
	if err != nil {
		t.Fatalf("ParseJS returned error: %v", err)
	}
	if skeleton.Language != LanguageJS {
		t.Fatalf("expected JS language, got %q", skeleton.Language)
	}
	if skeleton.Hash == "" || skeleton.Structure == "" || len(skeleton.NodeTypes) == 0 {
		t.Fatalf("expected populated skeleton: %+v", skeleton)
	}
	if !contains(skeleton.NodeTypes, "call:eval") || !contains(skeleton.NodeTypes, "member:cookie") {
		t.Fatalf("expected eval/cookie nodes, got %+v", skeleton.NodeTypes)
	}
}

func TestSkeletonHashIsDeterministic(t *testing.T) {
	first, err := ParseJS("alert(1)")
	if err != nil {
		t.Fatalf("ParseJS first returned error: %v", err)
	}
	second, err := ParseJS("alert(1)")
	if err != nil {
		t.Fatalf("ParseJS second returned error: %v", err)
	}
	if first.Hash != second.Hash || first.Structure != second.Structure {
		t.Fatalf("expected deterministic skeletons:\n%+v\n%+v", first, second)
	}
}

func TestSkeletonNormalizesLiteralValues(t *testing.T) {
	first, err := ParseSQL("SELECT id FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("ParseSQL first returned error: %v", err)
	}
	second, err := ParseSQL("SELECT name FROM users WHERE id = 999")
	if err != nil {
		t.Fatalf("ParseSQL second returned error: %v", err)
	}
	if first.Structure != second.Structure {
		t.Fatalf("expected normalized structures to match:\n%s\n%s", first.Structure, second.Structure)
	}
	if first.Hash != second.Hash {
		t.Fatalf("expected normalized hashes to match:\n%s\n%s", first.Hash, second.Hash)
	}
}

func TestDifferentStructuresProduceDifferentHashes(t *testing.T) {
	first, err := ParseJS("alert(1)")
	if err != nil {
		t.Fatalf("ParseJS first returned error: %v", err)
	}
	second, err := ParseJS("location.href='//evil'")
	if err != nil {
		t.Fatalf("ParseJS second returned error: %v", err)
	}
	if first.Hash == second.Hash {
		t.Fatalf("expected different structures to produce different hashes: %s", first.Hash)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

package jsparser

import (
	"strings"
	"testing"
)

func TestParseAlertCall(t *testing.T) {
	ast, err := Parse("alert(1)")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if ast.Root == nil || len(ast.Root.Children) != 1 {
		t.Fatal("expected one root expression")
	}
	call := ast.Root.Children[0]
	if call.Type != NodeCall || call.Value != "alert" {
		t.Fatalf("expected alert call, got %s %q", call.Type, call.Value)
	}
	if ast.Skeleton == "" || ast.SkeletonHash == "" {
		t.Fatal("expected skeleton and hash")
	}
	if !strings.Contains(ast.Skeleton, "call:alert") || !strings.Contains(ast.Skeleton, "number") {
		t.Fatalf("expected call and number in skeleton, got %q", ast.Skeleton)
	}
}

func TestParseEvalDocumentCookie(t *testing.T) {
	ast, err := Parse("eval(document.cookie)")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !strings.Contains(ast.Skeleton, "call:eval") {
		t.Fatalf("expected eval call in skeleton, got %q", ast.Skeleton)
	}
	if !strings.Contains(ast.Skeleton, "member:cookie") {
		t.Fatalf("expected cookie member in skeleton, got %q", ast.Skeleton)
	}
}

func TestParseLocationHrefAssignment(t *testing.T) {
	ast, err := Parse(`location.href="//evil"`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	expr := ast.Root.Children[0]
	if expr.Type != NodeAssignment {
		t.Fatalf("expected assignment, got %s", expr.Type)
	}
	if !strings.Contains(ast.Skeleton, "assign:=") || !strings.Contains(ast.Skeleton, "member:href") {
		t.Fatalf("expected assignment and href member in skeleton, got %q", ast.Skeleton)
	}
}

func TestParseDocumentCookieIndex(t *testing.T) {
	ast, err := Parse(`document["cookie"]`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	expr := ast.Root.Children[0]
	if expr.Type != NodeIndex {
		t.Fatalf("expected index expression, got %s", expr.Type)
	}
	if !strings.Contains(ast.Skeleton, "index:cookie") || !strings.Contains(ast.Skeleton, "string") {
		t.Fatalf("expected index and string in skeleton, got %q", ast.Skeleton)
	}
}

func TestParseSemicolonSeparatedExpressions(t *testing.T) {
	ast, err := Parse(`a=1;alert(document["cookie"])`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(ast.Root.Children) != 2 {
		t.Fatalf("expected two root expressions, got %d", len(ast.Root.Children))
	}
	if !strings.Contains(ast.Skeleton, "call:alert") || !strings.Contains(ast.Skeleton, "index:cookie") {
		t.Fatalf("expected alert call and cookie index in skeleton, got %q", ast.Skeleton)
	}
}

func TestParseArrayAndObjectLiterals(t *testing.T) {
	ast, err := Parse(`fn({cookie: document.cookie, n: 1}, ["x", 2])`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	for _, want := range []string{"call:fn", "object", "prop:cookie", "array"} {
		if !strings.Contains(ast.Skeleton, want) {
			t.Fatalf("expected %q in skeleton, got %q", want, ast.Skeleton)
		}
	}
}

func TestParseComments(t *testing.T) {
	ast, err := Parse("alert(1)//probe")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(ast.Comments) != 1 {
		t.Fatalf("expected one comment, got %d", len(ast.Comments))
	}
	if !strings.Contains(ast.Skeleton, "comment") {
		t.Fatalf("expected comment in skeleton, got %q", ast.Skeleton)
	}
}

func TestParseMalformedJS(t *testing.T) {
	_, err := Parse("alert(")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if _, ok := err.(*ParseError); !ok {
		t.Fatalf("expected ParseError, got %T", err)
	}
}

func TestSkeletonNormalizesLiterals(t *testing.T) {
	first, err := Parse("alert(1)")
	if err != nil {
		t.Fatalf("Parse first returned error: %v", err)
	}
	second, err := Parse("alert(999)")
	if err != nil {
		t.Fatalf("Parse second returned error: %v", err)
	}
	if first.Skeleton != second.Skeleton {
		t.Fatalf("expected normalized skeletons to match:\n%s\n%s", first.Skeleton, second.Skeleton)
	}
	if first.SkeletonHash != second.SkeletonHash {
		t.Fatalf("expected normalized hashes to match:\n%s\n%s", first.SkeletonHash, second.SkeletonHash)
	}
}

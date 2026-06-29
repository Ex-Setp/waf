package sqlparser

import (
	"strings"
	"testing"
)

func TestParseSelectStatement(t *testing.T) {
	ast, err := Parse("SELECT id, name FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if ast.Statement != StatementSelect {
		t.Fatalf("expected select statement, got %q", ast.Statement)
	}
	if ast.Root == nil || len(ast.Root.Children) == 0 {
		t.Fatal("expected root children")
	}
	if ast.Skeleton == "" || ast.SkeletonHash == "" {
		t.Fatal("expected skeleton and hash")
	}
	if !strings.Contains(ast.Skeleton, "clause:where") {
		t.Fatalf("expected where clause in skeleton, got %q", ast.Skeleton)
	}
}

func TestParseUnionSelectPayload(t *testing.T) {
	ast, err := Parse("SELECT id FROM users WHERE id=1 UNION SELECT username, password FROM admins")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if ast.Statement != StatementUnion {
		t.Fatalf("expected union statement, got %q", ast.Statement)
	}
	if !strings.Contains(ast.Skeleton, "union") {
		t.Fatalf("expected union skeleton, got %q", ast.Skeleton)
	}
}

func TestParseFunctionCallPayload(t *testing.T) {
	ast, err := Parse("SELECT concat(username, ':', password) FROM users")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !strings.Contains(ast.Skeleton, "func:concat") {
		t.Fatalf("expected function in skeleton, got %q", ast.Skeleton)
	}
}

func TestParseComments(t *testing.T) {
	ast, err := Parse("SELECT id FROM users -- trailing probe")
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

func TestParseMalformedSQL(t *testing.T) {
	_, err := Parse("SELECT concat(username")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if _, ok := err.(*ParseError); !ok {
		t.Fatalf("expected ParseError, got %T", err)
	}
}

func TestSkeletonNormalizesLiterals(t *testing.T) {
	first, err := Parse("SELECT id FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("Parse first returned error: %v", err)
	}
	second, err := Parse("SELECT name FROM users WHERE id = 999")
	if err != nil {
		t.Fatalf("Parse second returned error: %v", err)
	}
	if first.Skeleton != second.Skeleton {
		t.Fatalf("expected normalized skeletons to match:\n%s\n%s", first.Skeleton, second.Skeleton)
	}
}

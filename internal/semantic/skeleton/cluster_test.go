package skeleton

import (
	"strings"
	"testing"
)

func TestClusterByTreeEditDistanceSQLiPayloads(t *testing.T) {
	first := mustParseSQLSkeleton(t, "SELECT id FROM users WHERE id=1 UNION SELECT username FROM admins")
	second := mustParseSQLSkeleton(t, "SELECT name FROM users WHERE uid=999 UNION SELECT password FROM admins")
	unrelated := mustParseSQLSkeleton(t, "SELECT count(*) FROM visits")

	clusters := ClusterByTreeEditDistance([]*ASTSkeleton{first, unrelated, second})
	if len(clusters) != 1 {
		t.Fatalf("expected one SQLi cluster, got %d: %+v", len(clusters), clusters)
	}
	cluster := clusters[0]
	if cluster.Language != LanguageSQL {
		t.Fatalf("expected SQL cluster, got %q", cluster.Language)
	}
	for _, want := range []string{"statement:select", "union", "clause:where"} {
		if !contains(cluster.NodeTypes, want) {
			t.Fatalf("expected common node %q in %+v", want, cluster.NodeTypes)
		}
	}
	if contains(cluster.NodeTypes, "wildcard") {
		t.Fatalf("unrelated wildcard-only shape leaked into SQLi cluster: %+v", cluster.NodeTypes)
	}
	if cluster.Hash == "" || cluster.Structure == "" {
		t.Fatalf("expected populated cluster fingerprint: %+v", cluster)
	}
}

func TestClusterByTreeEditDistanceXSSPayloads(t *testing.T) {
	first := mustParseJSSkeleton(t, "eval(document.cookie)")
	second := mustParseJSSkeleton(t, "eval(location.hash)")
	unrelated := mustParseJSSkeleton(t, "location.href='//evil'")

	clusters := ClusterByTreeEditDistance([]*ASTSkeleton{unrelated, second, first})
	if len(clusters) != 1 {
		t.Fatalf("expected one XSS cluster, got %d: %+v", len(clusters), clusters)
	}
	cluster := clusters[0]
	if cluster.Language != LanguageJS {
		t.Fatalf("expected JS cluster, got %q", cluster.Language)
	}
	for _, want := range []string{"program", "call:eval", "identifier"} {
		if !contains(cluster.NodeTypes, want) {
			t.Fatalf("expected common node %q in %+v", want, cluster.NodeTypes)
		}
	}
	if contains(cluster.NodeTypes, "member:cookie") || contains(cluster.NodeTypes, "member:hash") {
		t.Fatalf("variant-specific member leaked into common cluster: %+v", cluster.NodeTypes)
	}
}

func TestClusterByTreeEditDistanceSeparatesLanguages(t *testing.T) {
	sqlFirst := mustParseSQLSkeleton(t, "SELECT id FROM users WHERE id=1 UNION SELECT username FROM admins")
	sqlSecond := mustParseSQLSkeleton(t, "SELECT name FROM users WHERE uid=2 UNION SELECT password FROM admins")
	jsFirst := mustParseJSSkeleton(t, "eval(document.cookie)")
	jsSecond := mustParseJSSkeleton(t, "eval(location.hash)")

	clusters := ClusterByTreeEditDistance([]*ASTSkeleton{jsSecond, sqlFirst, jsFirst, sqlSecond})
	if len(clusters) != 2 {
		t.Fatalf("expected SQL and JS clusters, got %d: %+v", len(clusters), clusters)
	}
	if clusters[0].Language == clusters[1].Language {
		t.Fatalf("expected language-separated clusters, got %+v", clusters)
	}
}

func TestClusterByTreeEditDistanceIgnoresSingletonsAndDuplicates(t *testing.T) {
	first := mustParseJSSkeleton(t, "alert(1)")
	duplicate := mustParseJSSkeleton(t, "alert(1)")
	unrelated := mustParseJSSkeleton(t, "location.href='//evil'")

	clusters := ClusterByTreeEditDistance([]*ASTSkeleton{nil, first, duplicate, unrelated})
	if len(clusters) != 0 {
		t.Fatalf("expected no non-singleton clusters after duplicate compaction, got %+v", clusters)
	}
}

func TestClusterByTreeEditDistanceIsDeterministic(t *testing.T) {
	first := mustParseSQLSkeleton(t, "SELECT id FROM users WHERE id=1 UNION SELECT username FROM admins")
	second := mustParseSQLSkeleton(t, "SELECT name FROM users WHERE uid=2 UNION SELECT password FROM admins")

	left := ClusterByTreeEditDistance([]*ASTSkeleton{first, second})
	right := ClusterByTreeEditDistance([]*ASTSkeleton{second, first})
	if len(left) != 1 || len(right) != 1 {
		t.Fatalf("expected one cluster from both runs: %+v %+v", left, right)
	}
	if left[0].Hash != right[0].Hash || left[0].Structure != right[0].Structure {
		t.Fatalf("expected deterministic cluster fingerprint:\n%+v\n%+v", left[0], right[0])
	}
}

func mustParseSQLSkeleton(t *testing.T, input string) *ASTSkeleton {
	t.Helper()
	skeleton, err := ParseSQL(input)
	if err != nil {
		t.Fatalf("ParseSQL(%q) returned error: %v", input, err)
	}
	return skeleton
}

func mustParseJSSkeleton(t *testing.T, input string) *ASTSkeleton {
	t.Helper()
	skeleton, err := ParseJS(input)
	if err != nil {
		t.Fatalf("ParseJS(%q) returned error: %v", input, err)
	}
	if strings.TrimSpace(skeleton.Structure) == "" {
		t.Fatalf("empty skeleton for %q", input)
	}
	return skeleton
}

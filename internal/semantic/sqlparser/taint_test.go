package sqlparser

import (
	"strings"
	"testing"
)

func TestAnalyzeTaintDetectsMysqlQuerySink(t *testing.T) {
	payload := "' OR '1'='1"
	quotedPayload := quoteSQL(payload)
	query := "SELECT mysql_query(concat('SELECT * FROM users WHERE name=', " + quotedPayload + "))"
	ast, err := Parse(query)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "name", Value: quotedPayload}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	flow := graph.Flows[0]
	if flow.Sink != "mysql_query" {
		t.Fatalf("expected mysql_query sink, got %q", flow.Sink)
	}
	if flow.Source.Name != "name" || flow.Risk != "high" {
		t.Fatalf("unexpected flow: %+v", flow)
	}
	if !strings.Contains(graph.String(), "function:mysql_query") || !strings.Contains(graph.String(), quotedPayload) {
		t.Fatalf("expected graph to include path through sink and tainted source, got %q", graph.String())
	}
}

func TestAnalyzeTaintPropagatesThroughNestedExecSink(t *testing.T) {
	payload := "1 UNION SELECT username, password FROM admins"
	query := "SELECT exec(concat('id=', " + quoteSQL(payload) + ")) FROM audit"
	ast, err := Parse(query)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "id", Value: quoteSQL(payload)}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "exec" {
		t.Fatalf("expected exec sink, got %q", graph.Flows[0].Sink)
	}
}

func TestAnalyzeTaintIgnoresUntaintedSink(t *testing.T) {
	ast, err := Parse("SELECT mysql_query('SELECT id FROM users WHERE id = 1')")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "missing", Value: "'not present'"}})
	if len(graph.Flows) != 0 {
		t.Fatalf("expected no taint flows, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.String() != "" {
		t.Fatalf("expected empty graph string, got %q", graph.String())
	}
}

func TestAnalyzeTaintMatchesSourceByOffset(t *testing.T) {
	payload := "../../etc/passwd"
	quotedPayload := quoteSQL(payload)
	query := "SELECT load_file(" + quotedPayload + ")"
	ast, err := Parse(query)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	start := strings.Index(query, quotedPayload)
	if start < 0 {
		t.Fatal("payload not found in query")
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "file", Start: start, End: start + len(quotedPayload)}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "load_file" {
		t.Fatalf("expected load_file sink, got %q", graph.Flows[0].Sink)
	}
}

func quoteSQL(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "\\'") + "'"
}

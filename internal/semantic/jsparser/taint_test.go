package jsparser

import (
	"strings"
	"testing"
)

func TestAnalyzeTaintDetectsEvalLocationHash(t *testing.T) {
	ast, err := Parse("eval(location.hash)")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "hash", Value: "hash"}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "eval" {
		t.Fatalf("expected eval sink, got %q", graph.Flows[0].Sink)
	}
	if !strings.Contains(graph.String(), "call:eval") || !strings.Contains(graph.String(), "hash") {
		t.Fatalf("expected eval flow graph with hash source, got %q", graph.String())
	}
}

func TestAnalyzeTaintDetectsDocumentWriteSink(t *testing.T) {
	ast, err := Parse(`document.write("<img src=x onerror=alert(1)>")`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	payload := `"<img src=x onerror=alert(1)>"`
	graph := AnalyzeTaint(ast, []TaintSource{{Name: "body", Value: payload}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "document.write" {
		t.Fatalf("expected document.write sink, got %q", graph.Flows[0].Sink)
	}
}

func TestAnalyzeTaintDetectsInnerHTMLAssignment(t *testing.T) {
	ast, err := Parse(`element.innerHTML = userInput`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "param", Value: "userInput"}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "element.innerhtml" {
		t.Fatalf("expected element.innerhtml sink, got %q", graph.Flows[0].Sink)
	}
}

func TestAnalyzeTaintDetectsLocationHrefAssignment(t *testing.T) {
	ast, err := Parse(`location.href = url`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "url", Value: "url"}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "location.href" {
		t.Fatalf("expected location.href sink, got %q", graph.Flows[0].Sink)
	}
}

func TestAnalyzeTaintDetectsSetTimeoutSink(t *testing.T) {
	ast, err := Parse(`setTimeout(code, 0)`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "code", Value: "code"}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "settimeout" {
		t.Fatalf("expected settimeout sink, got %q", graph.Flows[0].Sink)
	}
}

func TestAnalyzeTaintPropagatesAssignments(t *testing.T) {
	ast, err := Parse(`x = userInput; eval(x)`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "param", Value: "userInput"}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "eval" {
		t.Fatalf("expected eval sink, got %q", graph.Flows[0].Sink)
	}
}

func TestAnalyzeTaintMatchesOffsetSource(t *testing.T) {
	input := `document.writeln(fragment)`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	start := strings.Index(input, "fragment")
	if start < 0 {
		t.Fatal("source not found")
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "fragment", Start: start, End: start + len("fragment")}})
	if len(graph.Flows) != 1 {
		t.Fatalf("expected one taint flow, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.Flows[0].Sink != "document.writeln" {
		t.Fatalf("expected document.writeln sink, got %q", graph.Flows[0].Sink)
	}
}

func TestAnalyzeTaintIgnoresSafeUntaintedSink(t *testing.T) {
	ast, err := Parse(`eval("1 + 1")`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	graph := AnalyzeTaint(ast, []TaintSource{{Name: "missing", Value: "notPresent"}})
	if len(graph.Flows) != 0 {
		t.Fatalf("expected no taint flows, got %d: %s", len(graph.Flows), graph.String())
	}
	if graph.String() != "" {
		t.Fatalf("expected empty graph string, got %q", graph.String())
	}
}

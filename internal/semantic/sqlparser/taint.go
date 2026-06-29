package sqlparser

import (
	"fmt"
	"sort"
	"strings"
)

// TaintSource marks untrusted user-controlled data in the parsed SQL AST.
type TaintSource struct {
	Name  string
	Value string
	Start int
	End   int
}

// TaintFlow describes propagation of tainted data through the SQL AST.
type TaintFlow struct {
	Source TaintSource
	Path   []string
	Sink   string
	Risk   string
}

// TaintGraph is the deterministic output of a taint analysis run.
type TaintGraph struct {
	Flows []TaintFlow
}

var highRiskSinks = map[string]struct{}{
	"eval":        {},
	"exec":        {},
	"execute":     {},
	"mysql_query": {},
	"query":       {},
	"prepare":     {},
	"load_file":   {},
}

// AnalyzeTaint marks user-controlled AST nodes, propagates taint upward, and
// reports high-risk sinks reached by tainted data.
func AnalyzeTaint(ast *AST, sources []TaintSource) TaintGraph {
	if ast == nil || ast.Root == nil || len(sources) == 0 {
		return TaintGraph{}
	}

	flowsByKey := make(map[string]TaintFlow)
	analyzeNodeTaint(ast.Root, sources, nil, flowsByKey)

	flows := make([]TaintFlow, 0, len(flowsByKey))
	for _, flow := range flowsByKey {
		flows = append(flows, flow)
	}
	sort.Slice(flows, func(i, j int) bool {
		return flowSortKey(flows[i]) < flowSortKey(flows[j])
	})

	return TaintGraph{Flows: flows}
}

// String renders the graph in deterministic source -> path -> sink form.
func (g TaintGraph) String() string {
	if len(g.Flows) == 0 {
		return ""
	}

	parts := make([]string, 0, len(g.Flows))
	for _, flow := range g.Flows {
		sourceLabel := flow.Source.Name
		if flow.Source.Value != "" {
			sourceLabel = fmt.Sprintf("%s=%s", sourceLabel, flow.Source.Value)
		}
		parts = append(parts, fmt.Sprintf("%s -> %s -> %s [%s]", sourceLabel, strings.Join(flow.Path, " -> "), flow.Sink, flow.Risk))
	}
	return strings.Join(parts, "\n")
}

func analyzeNodeTaint(node *Node, sources []TaintSource, ancestors []string, flows map[string]TaintFlow) []TaintSource {
	if node == nil {
		return nil
	}

	path := appendNodePath(ancestors, node)
	var tainted []TaintSource
	for _, source := range sources {
		if nodeMatchesSource(node, source) {
			tainted = appendUniqueSource(tainted, source)
		}
	}

	for _, child := range node.Children {
		for _, source := range analyzeNodeTaint(child, sources, path, flows) {
			tainted = appendUniqueSource(tainted, source)
		}
	}

	if len(tainted) == 0 {
		return nil
	}

	if sink, ok := detectSink(node); ok {
		for _, source := range tainted {
			flow := TaintFlow{Source: source, Path: path, Sink: sink, Risk: "high"}
			flows[flowSortKey(flow)] = flow
		}
	}

	return tainted
}

func nodeMatchesSource(node *Node, source TaintSource) bool {
	if source.Value != "" && node.Value == source.Value {
		return true
	}
	if source.Start >= 0 && source.End > source.Start && node.Start <= source.Start && node.End >= source.End {
		return true
	}
	return false
}

func detectSink(node *Node) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(node.Value))
	if value == "" {
		return "", false
	}

	if node.Type == NodeFunction {
		if _, ok := highRiskSinks[value]; ok {
			return value, true
		}
	}

	if node.Type == NodeClause && value == "into" {
		return "into", true
	}

	if node.Type == NodeIdentifier {
		if value == "outfile" || value == "dumpfile" {
			return value, true
		}
	}

	return "", false
}

func appendNodePath(path []string, node *Node) []string {
	next := make([]string, 0, len(path)+1)
	next = append(next, path...)
	next = append(next, nodeLabel(node))
	return next
}

func nodeLabel(node *Node) string {
	if node == nil {
		return "<nil>"
	}
	if node.Value == "" {
		return string(node.Type)
	}
	return fmt.Sprintf("%s:%s", node.Type, strings.ToLower(node.Value))
}

func appendUniqueSource(sources []TaintSource, source TaintSource) []TaintSource {
	key := sourceKey(source)
	for _, existing := range sources {
		if sourceKey(existing) == key {
			return sources
		}
	}
	return append(sources, source)
}

func sourceKey(source TaintSource) string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%d", source.Name, source.Value, source.Start, source.End)
}

func flowSortKey(flow TaintFlow) string {
	return sourceKey(flow.Source) + "\x00" + strings.Join(flow.Path, "\x00") + "\x00" + flow.Sink + "\x00" + flow.Risk
}

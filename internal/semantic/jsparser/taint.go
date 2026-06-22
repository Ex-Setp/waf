package jsparser

import (
	"fmt"
	"sort"
	"strings"
)

// TaintSource marks untrusted user-controlled data in the parsed JS AST.
type TaintSource struct {
	Name  string
	Value string
	Start int
	End   int
}

// TaintFlow describes propagation of tainted data through the JS AST.
type TaintFlow struct {
	Source TaintSource
	Path   []string
	Sink   string
	Risk   string
}

// TaintGraph is the deterministic output of a JS taint analysis run.
type TaintGraph struct {
	Flows []TaintFlow
}

type taintState struct {
	bindings map[string][]TaintSource
	flows    map[string]TaintFlow
}

// AnalyzeTaint marks user-controlled AST nodes, propagates taint through JS
// expressions, and reports high-risk XSS sinks reached by tainted data.
func AnalyzeTaint(ast *AST, sources []TaintSource) TaintGraph {
	if ast == nil || ast.Root == nil || len(sources) == 0 {
		return TaintGraph{}
	}

	state := &taintState{bindings: make(map[string][]TaintSource), flows: make(map[string]TaintFlow)}
	state.eval(ast.Root, sources, nil)

	flows := make([]TaintFlow, 0, len(state.flows))
	for _, flow := range state.flows {
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

func (s *taintState) eval(node *Node, sources []TaintSource, ancestors []string) []TaintSource {
	if node == nil {
		return nil
	}

	path := appendNodePath(ancestors, node)
	tainted := s.directTaint(node, sources)

	switch node.Type {
	case NodeProgram, NodeArray, NodeObject, NodeProperty:
		for _, child := range node.Children {
			tainted = appendUniqueSources(tainted, s.eval(child, sources, path)...)
		}
	case NodeIdentifier:
		tainted = appendUniqueSources(tainted, s.bindings[node.Value]...)
	case NodeMember, NodeIndex:
		for _, child := range node.Children {
			tainted = appendUniqueSources(tainted, s.eval(child, sources, path)...)
		}
		if len(tainted) == 0 {
			tainted = appendUniqueSources(tainted, s.bindings[accessPath(node)]...)
		}
	case NodeCall:
		callee, args := splitCall(node)
		calleeTaint := s.eval(callee, sources, path)
		tainted = appendUniqueSources(tainted, calleeTaint...)
		argTaints := make([][]TaintSource, 0, len(args))
		for _, arg := range args {
			argTaint := s.eval(arg, sources, path)
			argTaints = append(argTaints, argTaint)
			tainted = appendUniqueSources(tainted, argTaint...)
		}
		for _, source := range callSinkSources(node, argTaints, tainted) {
			s.recordFlow(source, path, callSinkName(node))
		}
	case NodeAssignment:
		left, right := binaryChildren(node)
		rightTaint := s.eval(right, sources, path)
		leftTaint := s.eval(left, sources, path)
		tainted = appendUniqueSources(tainted, leftTaint...)
		tainted = appendUniqueSources(tainted, rightTaint...)
		if len(rightTaint) > 0 {
			if name := accessPath(left); name != "" {
				s.bindings[name] = appendUniqueSources(s.bindings[name], rightTaint...)
			}
		}
		if sink := assignmentSinkName(left); sink != "" {
			for _, source := range rightTaint {
				s.recordFlow(source, path, sink)
			}
		}
	case NodeBinary, NodeUnary:
		for _, child := range node.Children {
			tainted = appendUniqueSources(tainted, s.eval(child, sources, path)...)
		}
	default:
		for _, child := range node.Children {
			tainted = appendUniqueSources(tainted, s.eval(child, sources, path)...)
		}
	}

	return tainted
}

func (s *taintState) directTaint(node *Node, sources []TaintSource) []TaintSource {
	var tainted []TaintSource
	for _, source := range sources {
		if nodeMatchesSource(node, source) {
			tainted = appendUniqueSource(tainted, source)
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

func splitCall(node *Node) (*Node, []*Node) {
	if node == nil || len(node.Children) == 0 {
		return nil, nil
	}
	return node.Children[0], node.Children[1:]
}

func callSinkSources(node *Node, argTaints [][]TaintSource, allTaint []TaintSource) []TaintSource {
	if node == nil || node.Type != NodeCall {
		return nil
	}
	name := callSinkName(node)
	if name == "" {
		return nil
	}
	if isFunctionConstructorSink(name) {
		return allTaint
	}
	var tainted []TaintSource
	for _, argTaint := range argTaints {
		tainted = appendUniqueSources(tainted, argTaint...)
	}
	return tainted
}

func callSinkName(node *Node) string {
	if node == nil || node.Type != NodeCall {
		return ""
	}
	name := strings.ToLower(accessPath(node.Children[0]))
	if name == "" {
		name = strings.ToLower(node.Value)
	}
	switch name {
	case "eval", "function", "settimeout", "setinterval", "document.write", "document.writeln", "insertadjacenthtml":
		return name
	default:
		if strings.HasSuffix(name, ".insertadjacenthtml") {
			return name
		}
		return ""
	}
}

func assignmentSinkName(left *Node) string {
	name := strings.ToLower(accessPath(left))
	if name == "" {
		return ""
	}
	parts := strings.Split(name, ".")
	last := parts[len(parts)-1]
	switch last {
	case "innerhtml", "outerhtml", "srcdoc":
		return name
	case "href":
		if len(parts) >= 1 && parts[0] == "location" {
			return name
		}
		return ""
	default:
		if strings.HasPrefix(last, "on") && len(last) > 2 {
			return name
		}
		return ""
	}
}

func isFunctionConstructorSink(name string) bool {
	return strings.EqualFold(name, "function")
}

func binaryChildren(node *Node) (*Node, *Node) {
	if node == nil || len(node.Children) < 2 {
		return nil, nil
	}
	return node.Children[0], node.Children[1]
}

func accessPath(node *Node) string {
	if node == nil {
		return ""
	}
	switch node.Type {
	case NodeIdentifier:
		return node.Value
	case NodeMember:
		if len(node.Children) == 0 {
			return node.Value
		}
		base := accessPath(node.Children[0])
		if base == "" {
			return node.Value
		}
		return base + "." + node.Value
	case NodeIndex:
		if len(node.Children) == 0 {
			return node.Value
		}
		base := accessPath(node.Children[0])
		prop := node.Value
		if prop == "" || prop == "[]" {
			return base
		}
		if base == "" {
			return prop
		}
		return base + "." + prop
	case NodeCall:
		if len(node.Children) > 0 {
			return accessPath(node.Children[0])
		}
		return node.Value
	default:
		return ""
	}
}

func (s *taintState) recordFlow(source TaintSource, path []string, sink string) {
	if sink == "" {
		return
	}
	flow := TaintFlow{Source: source, Path: path, Sink: sink, Risk: "high"}
	s.flows[flowSortKey(flow)] = flow
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

func appendUniqueSources(sources []TaintSource, additions ...TaintSource) []TaintSource {
	for _, source := range additions {
		sources = appendUniqueSource(sources, source)
	}
	return sources
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

package detection

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"aegis-waf/internal/semantic/entropy"
	"aegis-waf/internal/semantic/jsparser"
	"aegis-waf/internal/semantic/sqlparser"
)

const (
	SemanticEntropyRuleID  = 935000
	SemanticSQLTaintRuleID = 935001
	SemanticJSTaintRuleID  = 935002
)

type SemanticOptions struct {
	EntropyThreshold float64
	BlockOnEntropy   bool
	BlockOnTaint     bool
}

type SemanticEngine struct {
	base    Engine
	options SemanticOptions
}

type semanticSignal struct {
	id      int
	message string
	detail  string
	deny    bool
}

func NewSemanticEngine(base Engine, options SemanticOptions) *SemanticEngine {
	if options.EntropyThreshold <= 0 || options.EntropyThreshold > 1 {
		options.EntropyThreshold = entropy.DefaultThreatThreshold
	}
	if !options.BlockOnEntropy && !options.BlockOnTaint {
		options.BlockOnEntropy = true
		options.BlockOnTaint = true
	}
	return &SemanticEngine{base: base, options: options}
}

func (e *SemanticEngine) Start(ctx context.Context) error {
	if e.base == nil {
		return nil
	}
	return e.base.Start(ctx)
}

func (e *SemanticEngine) Stop(ctx context.Context) error {
	if e.base == nil {
		return nil
	}
	return e.base.Stop(ctx)
}

func (e *SemanticEngine) Reload(ctx context.Context) error {
	if e.base == nil {
		return nil
	}
	return e.base.Reload(ctx)
}

func (e *SemanticEngine) Inspect(ctx context.Context, req Request) (Result, error) {
	result := Result{Decision: DecisionAllow}
	if e.base != nil {
		baseResult, err := e.base.Inspect(ctx, req)
		if err != nil {
			return Result{}, err
		}
		result = baseResult
		if result.Decision == "" {
			result.Decision = DecisionAllow
		}
	}

	for _, signal := range analyzeSemanticRequest(req, e.options) {
		action := RuleActionLog
		if signal.deny {
			action = RuleActionDeny
			result.Decision = DecisionBlock
		}
		result.Matches = append(result.Matches, MatchedRule{ID: signal.id, Message: signal.message, Source: signal.detail, Action: action})
	}
	return result, nil
}

func (e *SemanticEngine) Rules() []Rule {
	var rules []Rule
	if e.base != nil {
		rules = append(rules, e.base.Rules()...)
	}
	rules = append(rules,
		Rule{ID: SemanticEntropyRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticEntropy", Pattern: fmt.Sprintf("> %.2f", e.options.EntropyThreshold), Action: semanticAction(e.options.BlockOnEntropy), Message: "semantic syntax entropy threshold exceeded", Source: "semantic", Enabled: true},
		Rule{ID: SemanticSQLTaintRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticSQLTaint", Pattern: "tainted high-risk SQL sink", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic SQL taint flow reached high-risk sink", Source: "semantic", Enabled: true},
		Rule{ID: SemanticJSTaintRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticJSTaint", Pattern: "tainted high-risk JS sink", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic JS taint flow reached high-risk sink", Source: "semantic", Enabled: true},
	)
	return rules
}

func (e *SemanticEngine) EnableRule(id int) error {
	if isSemanticRule(id) {
		return nil
	}
	if e.base == nil {
		return fmt.Errorf("rule %d not found", id)
	}
	return e.base.EnableRule(id)
}

func (e *SemanticEngine) DisableRule(id int) error {
	if isSemanticRule(id) {
		return nil
	}
	if e.base == nil {
		return fmt.Errorf("rule %d not found", id)
	}
	return e.base.DisableRule(id)
}

func analyzeSemanticRequest(req Request, options SemanticOptions) []semanticSignal {
	parts := requestParts(req)
	joined := strings.Join(parts, " ")
	var signals []semanticSignal

	if entropyResult := entropy.AnalyzeWithThreshold(joined, options.EntropyThreshold); entropyResult.Threat {
		signals = append(signals, semanticSignal{
			id:      SemanticEntropyRuleID,
			message: fmt.Sprintf("semantic syntax entropy %.4f exceeded threshold %.4f", entropyResult.Value, entropyResult.Threshold),
			detail:  "semantic/entropy",
			deny:    options.BlockOnEntropy,
		})
	}

	if graph := analyzeSQLTaint(parts); len(graph.Flows) > 0 {
		signals = append(signals, semanticSignal{
			id:      SemanticSQLTaintRuleID,
			message: "semantic SQL taint flow reached high-risk sink",
			detail:  "semantic/sqlparser: " + graph.String(),
			deny:    options.BlockOnTaint,
		})
	}

	if graph := analyzeJSTaint(parts); len(graph.Flows) > 0 {
		signals = append(signals, semanticSignal{
			id:      SemanticJSTaintRuleID,
			message: "semantic JS taint flow reached high-risk sink",
			detail:  "semantic/jsparser: " + graph.String(),
			deny:    options.BlockOnTaint,
		})
	}

	return signals
}

func analyzeSQLTaint(parts []string) sqlparser.TaintGraph {
	for _, part := range parts {
		ast, err := sqlparser.Parse(part)
		if err != nil {
			continue
		}
		graph := sqlparser.AnalyzeTaint(ast, sqlSources(part))
		if len(graph.Flows) > 0 {
			return graph
		}
	}
	return sqlparser.TaintGraph{}
}

func analyzeJSTaint(parts []string) jsparser.TaintGraph {
	for _, part := range parts {
		ast, err := jsparser.Parse(part)
		if err != nil {
			continue
		}
		graph := jsparser.AnalyzeTaint(ast, jsSources(part))
		if len(graph.Flows) > 0 {
			return graph
		}
	}
	return jsparser.TaintGraph{}
}

func sqlSources(input string) []sqlparser.TaintSource {
	values := suspiciousSourceValues(input, []string{"'", "\"", "union", "select", "../", "/etc/passwd"})
	sources := make([]sqlparser.TaintSource, 0, len(values))
	for _, value := range values {
		sources = append(sources, sqlparser.TaintSource{Name: "request", Value: value})
	}
	return sources
}

func jsSources(input string) []jsparser.TaintSource {
	values := suspiciousSourceValues(input, []string{"location", "document", "cookie", "hash", "search", "name", "innerHTML", "<script"})
	sources := make([]jsparser.TaintSource, 0, len(values))
	for _, value := range values {
		sources = append(sources, jsparser.TaintSource{Name: "request", Value: value})
	}
	return sources
}

func suspiciousSourceValues(input string, needles []string) []string {
	var values []string
	lower := strings.ToLower(input)
	for _, needle := range needles {
		if strings.Contains(lower, strings.ToLower(needle)) {
			values = append(values, needle)
		}
	}
	quoted := extractQuotedValues(input)
	values = append(values, quoted...)
	return uniqueStrings(values)
}

func extractQuotedValues(input string) []string {
	var values []string
	for index := 0; index < len(input); index++ {
		quote := input[index]
		if quote != '\'' && quote != '"' && quote != '`' {
			continue
		}
		for end := index + 1; end < len(input); end++ {
			if input[end] == quote && input[end-1] != '\\' {
				values = append(values, input[index:end+1])
				index = end
				break
			}
		}
	}
	return values
}

func requestParts(req Request) []string {
	var parts []string
	appendPart := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			parts = append(parts, value)
		}
	}
	appendPart(req.Method)
	appendPart(req.URI)
	appendPart(req.Body)
	for _, key := range sortedKeys(req.Args) {
		appendPart(key)
		for _, value := range req.Args[key] {
			appendPart(value)
		}
	}
	appendHeaderParts(req.Headers, appendPart)
	return uniqueStrings(parts)
}

func appendHeaderParts(headers http.Header, appendPart func(string)) {
	for _, key := range sortedHeaderKeys(headers) {
		appendPart(key)
		for _, value := range headers.Values(key) {
			appendPart(value)
		}
	}
}

func sortedKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedHeaderKeys(headers http.Header) []string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

func semanticAction(block bool) RuleAction {
	if block {
		return RuleActionDeny
	}
	return RuleActionLog
}

func isSemanticRule(id int) bool {
	return id == SemanticEntropyRuleID || id == SemanticSQLTaintRuleID || id == SemanticJSTaintRuleID
}

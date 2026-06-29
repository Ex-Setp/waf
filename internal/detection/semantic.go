package detection

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"aegis-waf/internal/normalizer"
	"aegis-waf/internal/semantic/entropy"
	"aegis-waf/internal/semantic/jsparser"
	"aegis-waf/internal/semantic/sqlparser"
)

const (
	SemanticEntropyRuleID  = 935000
	SemanticSQLTaintRuleID = 935001
	SemanticJSTaintRuleID  = 935002
	SemanticXSSChopRuleID  = 935003
	SemanticSQLChopRuleID  = 935004
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
	id              int
	message         string
	detail          string
	group           string
	severity        string
	score           int
	deny            bool
	normalizedValue string
	evidence        []string
}

type chopResult struct {
	Normalized string
	Evidence   []string
	Score      int
}

var (
	sqlBooleanBlindPattern = regexp.MustCompile(`(?i)(?:\bor\b|\band\b)\s+(?:'[^']*'\s*=\s*'[^']*'|\d+\s*=\s*\d+|true\s*=\s*true|false\s*=\s*false)`)
	sqlTimeBlindPattern    = regexp.MustCompile(`(?i)\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message)\s*\(`)
	sqlFunctionPattern     = regexp.MustCompile(`(?i)\b(?:load_file|extractvalue|updatexml|concat|char|substring|ascii|database|version|user|benchmark|sleep|pg_sleep)\s*\(`)
	sqlUnionPattern        = regexp.MustCompile(`(?i)\bunion(?:\s+all|\s+distinct)?\s+select\b`)
	sqlStackedPattern      = regexp.MustCompile(`(?i);\s*(?:select|insert|update|delete|drop|alter|create|exec|execute)\b`)
	xssEventPattern        = regexp.MustCompile(`(?i)\bon[a-z][a-z0-9_-]*\s*=`)
	xssDOMSinkPattern      = regexp.MustCompile(`(?i)\b(?:eval|settimeout|setinterval|function)\s*\(|(?:document\.(?:write|writeln)|insertadjacenthtml|innerhtml|outerhtml|srcdoc)\b`)
	xssTemplatePattern     = regexp.MustCompile(`(?i)(?:\{\{.*(?:constructor|alert|document|window|eval|location).*}}|<%.*(?:alert|eval|document|window).*%>|\$\{.*(?:alert|eval|document|window|location).*\})`)
)

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
		message := signal.message
		if signal.normalizedValue != "" {
			message += " | normalized=" + signal.normalizedValue
		}
		if len(signal.evidence) > 0 {
			message += " | evidence=" + strings.Join(signal.evidence, ",")
		}
		result.Matches = append(result.Matches, MatchedRule{ID: signal.id, Message: message, Source: signal.detail, Group: signal.group, Severity: signal.severity, Score: signal.score, Action: action, Evidence: signal.evidence})
		result.Score += signal.score
		result.Severity = maxSeverity(result.Severity, signal.severity)
	}
	return result, nil
}

func (e *SemanticEngine) Rules() []Rule {
	var rules []Rule
	if e.base != nil {
		rules = append(rules, e.base.Rules()...)
	}
	rules = append(rules,
		Rule{ID: SemanticEntropyRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticEntropy", Pattern: fmt.Sprintf("> %.2f", e.options.EntropyThreshold), Action: RuleActionLog, Message: "semantic syntax entropy threshold exceeded", Source: "semantic", Enabled: true},
		Rule{ID: SemanticSQLTaintRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticSQLTaint", Pattern: "tainted high-risk SQL sink", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic SQL taint flow reached high-risk sink", Source: "semantic", Enabled: true},
		Rule{ID: SemanticJSTaintRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticJSTaint", Pattern: "tainted high-risk JS sink", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic JS taint flow reached high-risk sink", Source: "semantic", Enabled: true},
		Rule{ID: SemanticXSSChopRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticXSSChop", Pattern: "html/js execution context", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic XSS execution context detected", Source: "semantic", Enabled: true},
		Rule{ID: SemanticSQLChopRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticSQLChop", Pattern: "SQL injection structure", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic SQL injection structure detected", Source: "semantic", Enabled: true},
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

	if entropyResult := entropy.AnalyzeWithThreshold(joined, options.EntropyThreshold); entropyResult.Threat && hasExecutableSemanticEvidence(parts) {
		signals = append(signals, semanticSignal{
			id:              SemanticEntropyRuleID,
			message:         fmt.Sprintf("semantic syntax entropy %.4f exceeded threshold %.4f", entropyResult.Value, entropyResult.Threshold),
			detail:          "semantic/entropy",
			group:           "semantic-entropy",
			severity:        "medium",
			score:           2,
			deny:            false,
			normalizedValue: joined,
			evidence:        []string{"entropy"},
		})
	}

	if graph := analyzeSQLTaint(parts); len(graph.Flows) > 0 {
		signals = append(signals, semanticSignal{
			id:              SemanticSQLTaintRuleID,
			message:         "semantic SQL taint flow reached high-risk sink",
			detail:          "semantic/sqlparser: " + graph.String(),
			group:           "sqli",
			severity:        "critical",
			score:           8,
			deny:            options.BlockOnTaint,
			normalizedValue: strings.Join(parts, " "),
			evidence:        []string{graph.String()},
		})
	}

	if sql := analyzeSQLChop(parts); len(sql.Evidence) > 0 {
		signals = append(signals, semanticSignal{
			id:              SemanticSQLChopRuleID,
			message:         "semantic SQL injection structure detected",
			detail:          "semantic/sqlchop",
			group:           "sqli",
			severity:        semanticSeverity(sql.Score, "critical"),
			score:           sql.Score,
			deny:            options.BlockOnTaint,
			normalizedValue: sql.Normalized,
			evidence:        sql.Evidence,
		})
	}

	if graph := analyzeJSTaint(parts); len(graph.Flows) > 0 {
		signals = append(signals, semanticSignal{
			id:              SemanticJSTaintRuleID,
			message:         "semantic JS taint flow reached high-risk sink",
			detail:          "semantic/jsparser: " + graph.String(),
			group:           "xss",
			severity:        "high",
			score:           7,
			deny:            options.BlockOnTaint,
			normalizedValue: strings.Join(parts, " "),
			evidence:        []string{graph.String()},
		})
	}

	if xss := analyzeXSSChop(parts); len(xss.Evidence) > 0 {
		signals = append(signals, semanticSignal{
			id:              SemanticXSSChopRuleID,
			message:         "semantic XSS execution context detected",
			detail:          "semantic/xsschop",
			group:           "xss",
			severity:        semanticSeverity(xss.Score, "high"),
			score:           xss.Score,
			deny:            options.BlockOnTaint,
			normalizedValue: xss.Normalized,
			evidence:        xss.Evidence,
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

func hasExecutableSemanticEvidence(parts []string) bool {
	for _, part := range parts {
		if len(analyzeSQLChop([]string{part}).Evidence) > 0 || len(analyzeXSSChop([]string{part}).Evidence) > 0 {
			return true
		}
	}
	return false
}

func analyzeSQLChop(parts []string) chopResult {
	evidence := map[string]bool{}
	normalizedParts := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := normalizeSemanticValue(part)
		if normalized == "" {
			continue
		}
		normalizedParts = append(normalizedParts, normalized)
		rawLower := strings.ToLower(part)
		if sqlUnionPattern.MatchString(normalized) {
			evidence["token:union_select"] = true
			evidence["structure:union_query"] = true
		}
		if sqlBooleanBlindPattern.MatchString(normalized) {
			evidence["token:boolean_condition"] = true
			evidence["structure:boolean_blind"] = true
		}
		if sqlTimeBlindPattern.MatchString(normalized) {
			evidence["token:time_delay_function"] = true
			evidence["structure:time_blind"] = true
		}
		if sqlFunctionPattern.MatchString(normalized) {
			evidence["structure:function_call"] = true
		}
		if strings.Contains(part, "/*") || strings.Contains(part, "--") || strings.Contains(part, "#") {
			evidence["structure:comment_bypass"] = true
		}
		if sqlStackedPattern.MatchString(normalized) {
			evidence["structure:stacked_statement"] = true
		}
		if (strings.Contains(rawLower, "%") || strings.Contains(rawLower, `\u`) || strings.Contains(rawLower, "%u")) && len(evidence) > 0 {
			evidence["normalization:encoded_payload"] = true
		}
	}
	list := sortedEvidence(evidence)
	if len(list) == 0 {
		return chopResult{}
	}
	return chopResult{Normalized: strings.Join(uniqueStrings(normalizedParts), " "), Evidence: list, Score: semanticEvidenceScore(list, 8)}
}

func analyzeXSSChop(parts []string) chopResult {
	evidence := map[string]bool{}
	normalizedParts := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := normalizeSemanticValue(part)
		if normalized == "" {
			continue
		}
		normalizedParts = append(normalizedParts, normalized)
		lower := strings.ToLower(part)
		normalizedLower := strings.ToLower(normalized)
		if strings.Contains(normalizedLower, "<script") && strings.Contains(normalizedLower, ">") {
			evidence["token:script_tag"] = true
			evidence["structure:html_execution_context"] = true
		}
		if strings.Contains(normalizedLower, "javascript:") {
			evidence["token:javascript_url"] = true
		}
		if strings.Contains(normalizedLower, "data:text/html") || strings.Contains(normalizedLower, "data:image/svg") || strings.Contains(normalizedLower, "data:application/xhtml") {
			evidence["token:data_url"] = true
		}
		if xssEventPattern.MatchString(normalized) {
			evidence["token:event_handler"] = true
			evidence["structure:html_execution_context"] = true
		}
		if xssDOMSinkPattern.MatchString(normalized) {
			evidence["structure:dom_sink"] = true
		}
		if strings.Contains(normalizedLower, "<svg") || strings.Contains(normalizedLower, "</svg") {
			evidence["structure:svg_context"] = true
		}
		if strings.Contains(normalizedLower, "<math") || strings.Contains(normalizedLower, "</math") {
			evidence["structure:mathml_context"] = true
		}
		if xssTemplatePattern.MatchString(normalized) {
			evidence["structure:template_payload"] = true
		}
		if (strings.Contains(lower, "%") || strings.Contains(lower, `\u`) || strings.Contains(lower, "&")) && len(evidence) > 0 {
			evidence["normalization:encoded_payload"] = true
		}
	}
	list := sortedEvidence(evidence)
	if len(list) == 0 {
		return chopResult{}
	}
	return chopResult{Normalized: strings.Join(uniqueStrings(normalizedParts), " "), Evidence: list, Score: semanticEvidenceScore(list, 7)}
}

func sortedEvidence(evidence map[string]bool) []string {
	out := make([]string, 0, len(evidence))
	for item := range evidence {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func normalizeSemanticValue(value string) string {
	normalized := normalizer.NormalizeValue(value)
	normalized = strings.Join(strings.Fields(normalized), " ")
	normalized = strings.ReplaceAll(normalized, "/ *", "/*")
	normalized = strings.ReplaceAll(normalized, "* /", "*/")
	return strings.TrimSpace(normalized)
}

func semanticEvidenceScore(evidence []string, base int) int {
	score := base
	for _, item := range evidence {
		switch {
		case strings.HasPrefix(item, "normalization:"):
			score++
		case strings.HasPrefix(item, "structure:"):
			score += 2
		default:
			score++
		}
	}
	if score > 12 {
		return 12
	}
	return score
}

func semanticSeverity(score int, fallback string) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 6:
		return "high"
	case fallback != "":
		return fallback
	default:
		return "medium"
	}
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
	return id == SemanticEntropyRuleID || id == SemanticSQLTaintRuleID || id == SemanticJSTaintRuleID || id == SemanticXSSChopRuleID || id == SemanticSQLChopRuleID
}

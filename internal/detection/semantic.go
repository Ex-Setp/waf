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
	SemanticRCEChopRuleID  = 935005
	SemanticSSRFChopRuleID = 935006
	SemanticUploadRuleID   = 935007
	SemanticProtoRuleID    = 935008
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
	rceSinkPattern         = regexp.MustCompile(`(?i)(?:runtime\.getruntime\(\)\.exec|processbuilder|subprocess\.(?:popen|run|call)|os\.system|child_process\.(?:exec|spawn)|\b(?:exec|execute|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|bash|sh)\b)`)
	rceChainPattern        = regexp.MustCompile("(?i)(?:&&|\\|\\||;|`|\\$\\(|\\|\\s*(?:sh|bash|powershell|cmd)\\b|\\b(?:cmd(?:\\.exe)?\\s+/c|powershell(?:\\.exe)?\\s+-(?:enc|encodedcommand|e)|(?:bash|sh)\\s+-c)\\b)")
	rceReconPattern        = regexp.MustCompile(`(?i)\b(?:whoami|id|uname(?:\s+-a)?|ifconfig|ipconfig|cat\s+/etc/passwd|type\s+c:\\windows\\win\.ini|nc\s+-e|bash\s+-i)\b`)
	rceDownloadExecPattern = regexp.MustCompile(`(?i)\b(?:curl|wget|invoke-webrequest|certutil|bitsadmin)\b.*(?:&&|;|\|\s*(?:sh|bash|powershell|cmd)\b)`)
	ssrfSinkPattern        = regexp.MustCompile(`(?i)\b(?:url|uri|target|dest|destination|endpoint|redirect|redirect_uri|return_url|next|callback|service|proxy|webhook|fetch|load|open|feed)\b`)
	ssrfInternalPattern    = regexp.MustCompile(`(?i)(?:https?://)?(?:127(?:\.\d{1,3}){3}|0\.0\.0\.0|10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2}|localhost(?::\d+)?(?:/|$)|\[::1\]|metadata\.google\.internal|100\.100\.100\.200)(?:[:/]|$)`)
	ssrfMetadataPattern    = regexp.MustCompile(`(?i)\b(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|169\.254\.170\.2)\b`)
	uploadFieldPattern     = regexp.MustCompile(`(?i)\b(?:upload|file|filename|avatar|image|attachment|multipart/form-data)\b`)
	webshellExtPattern     = regexp.MustCompile("(?i)\\.(?:php\\d*|phtml|phar|jsp|jspx|asp|aspx|ashx|cfm|cgi|pl)(?:[\\s\"';?]|$)")
	webshellCodePattern    = regexp.MustCompile(`(?i)(?:<\?php|<%@\s*page|eval\s*\(\s*\$_(?:post|get|request|cookie)|assert\s*\(\s*\$_(?:post|get|request)|system\s*\(\s*\$_(?:post|get|request)|shell_exec\s*\(\s*\$_(?:post|get|request)|base64_decode\s*\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)`)
	doubleExtPattern       = regexp.MustCompile(`(?i)\.(?:jpg|jpeg|png|gif|txt|pdf|doc|docx)\.(?:php\d*|phtml|jsp|jspx|asp|aspx|ashx|cgi|pl)\b`)
	uploadRiskPattern      = regexp.MustCompile(`(?i)\b(?:path_traversal|executable_extension|double_extension|content_type_mismatch|webshell_code)\b`)
	protoSchemePattern     = regexp.MustCompile(`(?i)\b(?:gopher|php|phar|expect|jar|dict|ldap|tftp|data):(?://)?`)
	protoCarrierPattern    = regexp.MustCompile(`(?i)\b(?:url|uri|resource|target|redirect|callback|next|service|endpoint|proxy|stream|schema|transport|dsn|include|load|open)\b`)
	protoExploitPattern    = regexp.MustCompile(`(?i)(?:php://filter/.+resource=|phar://|expect://|gopher://|dict://|jar:(?:https?|file):|data:(?:text/html|application/xhtml|image/svg\+xml))`)
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
		Rule{ID: SemanticRCEChopRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticRCEChop", Pattern: "command execution structure", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic command execution structure detected", Source: "semantic", Enabled: true},
		Rule{ID: SemanticSSRFChopRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticSSRFChop", Pattern: "ssrf target structure", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic SSRF target detected", Source: "semantic", Enabled: true},
		Rule{ID: SemanticUploadRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticUploadChop", Pattern: "upload webshell structure", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic upload webshell detected", Source: "semantic", Enabled: true},
		Rule{ID: SemanticProtoRuleID, Phase: 2, Variable: "REQUEST", Operator: "@semanticProtocolChop", Pattern: "dangerous protocol wrapper", Action: semanticAction(e.options.BlockOnTaint), Message: "semantic protocol wrapper detected", Source: "semantic", Enabled: true},
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

	if rce := analyzeRCEChop(parts); len(rce.Evidence) > 0 {
		signals = append(signals, semanticSignal{
			id:              SemanticRCEChopRuleID,
			message:         "semantic command execution structure detected",
			detail:          "semantic/rcechop",
			group:           "rce",
			severity:        semanticSeverity(rce.Score, "critical"),
			score:           rce.Score,
			deny:            options.BlockOnTaint,
			normalizedValue: rce.Normalized,
			evidence:        rce.Evidence,
		})
	}

	if ssrf := analyzeSSRFChop(parts); len(ssrf.Evidence) > 0 {
		signals = append(signals, semanticSignal{
			id:              SemanticSSRFChopRuleID,
			message:         "semantic SSRF target detected",
			detail:          "semantic/ssrfchop",
			group:           "ssrf",
			severity:        semanticSeverity(ssrf.Score, "high"),
			score:           ssrf.Score,
			deny:            options.BlockOnTaint,
			normalizedValue: ssrf.Normalized,
			evidence:        ssrf.Evidence,
		})
	}

	if upload := analyzeUploadChop(parts); len(upload.Evidence) > 0 {
		signals = append(signals, semanticSignal{
			id:              SemanticUploadRuleID,
			message:         "semantic upload webshell detected",
			detail:          "semantic/uploadchop",
			group:           "upload",
			severity:        semanticSeverity(upload.Score, "critical"),
			score:           upload.Score,
			deny:            options.BlockOnTaint,
			normalizedValue: upload.Normalized,
			evidence:        upload.Evidence,
		})
	}

	if proto := analyzeProtocolChop(parts); len(proto.Evidence) > 0 {
		signals = append(signals, semanticSignal{
			id:              SemanticProtoRuleID,
			message:         "semantic protocol wrapper detected",
			detail:          "semantic/protochop",
			group:           "protocol",
			severity:        semanticSeverity(proto.Score, "medium"),
			score:           proto.Score,
			deny:            options.BlockOnTaint,
			normalizedValue: proto.Normalized,
			evidence:        proto.Evidence,
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

func analyzeRCEChop(parts []string) chopResult {
	evidence := map[string]bool{}
	normalizedParts := make([]string, 0, len(parts))
	hasSink := false
	hasChain := false
	hasRecon := false
	hasDownloadExec := false
	for _, part := range parts {
		normalized := normalizeSemanticValue(part)
		if normalized == "" {
			continue
		}
		normalizedParts = append(normalizedParts, normalized)
		normalizedLower := strings.ToLower(normalized)
		if rceSinkPattern.MatchString(normalized) {
			evidence["token:command_sink"] = true
			hasSink = true
		}
		if rceChainPattern.MatchString(normalized) {
			evidence["structure:command_chain"] = true
			hasChain = true
		}
		if rceReconPattern.MatchString(normalized) {
			evidence["token:recon_command"] = true
			hasRecon = true
		}
		if rceDownloadExecPattern.MatchString(normalized) {
			evidence["token:download_execute"] = true
			evidence["structure:command_chain"] = true
			hasDownloadExec = true
			hasChain = true
		}
		if strings.Contains(normalizedLower, "/bin/sh") || strings.Contains(normalizedLower, "/bin/bash") || strings.Contains(normalizedLower, "cmd.exe") || strings.Contains(normalizedLower, "powershell") {
			evidence["token:shell_target"] = true
		}
		if hasEncodedIndicators(part) && len(evidence) > 0 {
			evidence["normalization:encoded_payload"] = true
		}
	}
	if !(hasDownloadExec || (hasSink && (hasChain || hasRecon))) {
		return chopResult{}
	}
	list := sortedEvidence(evidence)
	return chopResult{Normalized: strings.Join(uniqueStrings(normalizedParts), " "), Evidence: list, Score: semanticEvidenceScore(list, 8)}
}

func analyzeSSRFChop(parts []string) chopResult {
	evidence := map[string]bool{}
	normalizedParts := make([]string, 0, len(parts))
	hasSink := false
	hasInternalTarget := false
	for _, part := range parts {
		normalized := normalizeSemanticValue(part)
		if normalized == "" {
			continue
		}
		normalizedParts = append(normalizedParts, normalized)
		if ssrfSinkPattern.MatchString(normalized) {
			evidence["token:request_sink"] = true
			hasSink = true
		}
		if ssrfInternalPattern.MatchString(normalized) {
			evidence["structure:internal_host"] = true
			hasInternalTarget = true
		}
		if ssrfMetadataPattern.MatchString(normalized) {
			evidence["token:metadata_endpoint"] = true
			hasInternalTarget = true
		}
		if hasEncodedIndicators(part) && len(evidence) > 0 {
			evidence["normalization:encoded_payload"] = true
		}
	}
	if !(hasSink && hasInternalTarget) {
		return chopResult{}
	}
	list := sortedEvidence(evidence)
	return chopResult{Normalized: strings.Join(uniqueStrings(normalizedParts), " "), Evidence: list, Score: semanticEvidenceScore(list, 7)}
}

func analyzeUploadChop(parts []string) chopResult {
	evidence := map[string]bool{}
	normalizedParts := make([]string, 0, len(parts))
	hasUploadCarrier := false
	hasFilename := false
	hasWebshellExt := false
	hasWebshellCode := false
	hasDoubleExt := false
	hasPathTraversal := false
	hasContentMismatch := false
	for _, part := range parts {
		normalized := normalizeSemanticValue(part)
		if normalized == "" {
			continue
		}
		normalizedParts = append(normalizedParts, normalized)
		normalizedLower := strings.ToLower(normalized)
		if uploadFieldPattern.MatchString(normalized) {
			evidence["structure:upload_carrier"] = true
			hasUploadCarrier = true
		}
		if strings.Contains(normalizedLower, "filename=") {
			evidence["structure:multipart_filename"] = true
			hasFilename = true
		}
		if strings.Contains(normalizedLower, ".filename") {
			evidence["structure:file_metadata"] = true
			hasFilename = true
		}
		if webshellExtPattern.MatchString(normalized) {
			evidence["token:webshell_extension"] = true
			hasWebshellExt = true
		}
		if webshellCodePattern.MatchString(normalized) {
			evidence["token:webshell_code"] = true
			hasWebshellCode = true
		}
		if doubleExtPattern.MatchString(normalized) {
			evidence["structure:double_extension"] = true
			hasDoubleExt = true
		}
		if uploadRiskPattern.MatchString(normalized) {
			evidence["structure:file_risk"] = true
			if strings.Contains(normalizedLower, "path_traversal") {
				evidence["structure:path_traversal"] = true
				hasPathTraversal = true
			}
			if strings.Contains(normalizedLower, "content_type_mismatch") {
				evidence["structure:content_type_mismatch"] = true
				hasContentMismatch = true
			}
			if strings.Contains(normalizedLower, "executable_extension") {
				evidence["token:webshell_extension"] = true
				hasWebshellExt = true
			}
			if strings.Contains(normalizedLower, "double_extension") {
				evidence["structure:double_extension"] = true
				hasDoubleExt = true
			}
			if strings.Contains(normalizedLower, "webshell_code") {
				evidence["token:webshell_code"] = true
				hasWebshellCode = true
			}
		}
		if hasEncodedIndicators(part) && len(evidence) > 0 {
			evidence["normalization:encoded_payload"] = true
		}
	}
	if !(hasPathTraversal || hasContentMismatch || (hasWebshellCode && (hasWebshellExt || hasFilename || hasUploadCarrier)) || (hasDoubleExt && (hasFilename || hasUploadCarrier)) || (hasWebshellExt && (hasFilename || hasUploadCarrier))) {
		return chopResult{}
	}
	list := sortedEvidence(evidence)
	return chopResult{Normalized: strings.Join(uniqueStrings(normalizedParts), " "), Evidence: list, Score: semanticEvidenceScore(list, 8)}
}

func analyzeProtocolChop(parts []string) chopResult {
	evidence := map[string]bool{}
	normalizedParts := make([]string, 0, len(parts))
	hasScheme := false
	hasCarrier := false
	hasExploit := false
	hasSmuggling := false
	for _, part := range parts {
		normalized := normalizeSemanticValue(part)
		if normalized == "" {
			continue
		}
		normalizedParts = append(normalizedParts, normalized)
		normalizedLower := strings.ToLower(normalized)
		if protoSchemePattern.MatchString(normalized) {
			evidence["token:dangerous_scheme"] = true
			hasScheme = true
		}
		if protoCarrierPattern.MatchString(normalized) {
			evidence["structure:protocol_wrapper"] = true
			hasCarrier = true
		}
		if protoExploitPattern.MatchString(normalized) {
			evidence["structure:wrapper_payload"] = true
			hasExploit = true
		}
		if strings.Contains(normalizedLower, "%0d%0a") || strings.Contains(normalizedLower, "\r\n") || strings.Contains(normalizedLower, "/_*") {
			evidence["structure:protocol_smuggling"] = true
			hasSmuggling = true
		}
		if hasEncodedIndicators(part) && len(evidence) > 0 {
			evidence["normalization:encoded_payload"] = true
		}
	}
	if !(hasScheme && hasExploit && (hasCarrier || hasSmuggling)) {
		return chopResult{}
	}
	list := sortedEvidence(evidence)
	return chopResult{Normalized: strings.Join(uniqueStrings(normalizedParts), " "), Evidence: list, Score: semanticEvidenceScore(list, 6)}
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

func hasEncodedIndicators(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "%") || strings.Contains(lower, `\u`) || strings.Contains(lower, "%u") || strings.Contains(lower, "&")
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
	contentType := strings.ToLower(req.Headers.Get("Content-Type"))
	if !(strings.Contains(contentType, "multipart/form-data") && len(req.Args) > 0) {
		appendPart(req.Body)
	}
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
	return id == SemanticEntropyRuleID || id == SemanticSQLTaintRuleID || id == SemanticJSTaintRuleID || id == SemanticXSSChopRuleID || id == SemanticSQLChopRuleID || id == SemanticRCEChopRuleID || id == SemanticSSRFChopRuleID || id == SemanticUploadRuleID || id == SemanticProtoRuleID
}

package detection

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"aegis-waf/internal/crs"

	coraza "github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
)

type CorazaEngine struct {
	mu         sync.RWMutex
	manager    *crs.Manager
	waf        coraza.WAF
	supplement *Manager
	config     crs.Config
}

func NewCorazaEngine(manager *crs.Manager) (*CorazaEngine, error) {
	if manager == nil {
		manager = crs.NewManager(crs.Config{})
	}
	engine := &CorazaEngine{manager: manager, config: manager.Config()}
	if err := engine.Reload(context.Background()); err != nil && !engine.config.FailOpen {
		return nil, err
	}
	return engine, nil
}

func (e *CorazaEngine) Start(context.Context) error { return nil }
func (e *CorazaEngine) Stop(context.Context) error  { return nil }

func (e *CorazaEngine) Reload(ctx context.Context) error {
	if e == nil || e.manager == nil {
		return nil
	}
	cfg := e.manager.Config()
	if err := e.manager.Reload(ctx); err != nil && !cfg.FailOpen {
		return err
	}
	waf, err := buildCorazaWAF(cfg, e.manager.RuleFiles())
	if err != nil {
		if cfg.FailOpen {
			e.mu.Lock()
			e.config = cfg
			e.waf = nil
			e.supplement = nil
			e.mu.Unlock()
			return nil
		}
		return err
	}
	supplement, _ := NewManager(cfg.RulesDir, nil, nil, false)
	e.mu.Lock()
	e.config = cfg
	e.waf = waf
	e.supplement = supplement
	e.mu.Unlock()
	return nil
}

func (e *CorazaEngine) Inspect(ctx context.Context, req Request) (Result, error) {
	e.mu.RLock()
	waf := e.waf
	supplement := e.supplement
	cfg := e.config
	e.mu.RUnlock()
	if !cfg.Enabled || waf == nil {
		return Result{Decision: DecisionAllow}, nil
	}
	tx := waf.NewTransaction()
	defer tx.Close()

	tx.ProcessConnection("0.0.0.0", 0, "127.0.0.1", 0)
	tx.SetServerName(req.Headers.Get("Host"))
	if req.Headers.Get("Host") == "" {
		tx.SetServerName("localhost")
	}
	uri := req.URI
	if uri == "" {
		uri = "/"
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	tx.ProcessURI(uri, method, "HTTP/1.1")
	for key, values := range req.Headers {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	for key, values := range req.Args {
		for _, value := range values {
			tx.AddGetRequestArgument(key, value)
		}
	}
	var interruptions []*corazatypes.Interruption
	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		interruptions = append(interruptions, interruption)
	}
	if req.Body != "" {
		if interruption, _, err := tx.WriteRequestBody([]byte(req.Body)); err != nil {
			if !cfg.FailOpen {
				return Result{Decision: DecisionBlock, Severity: "high"}, fmt.Errorf("coraza request body: %w", err)
			}
		} else if interruption != nil {
			interruptions = append(interruptions, interruption)
		}
	}
	if interruption, err := tx.ProcessRequestBody(); err != nil {
		if !cfg.FailOpen {
			return Result{Decision: DecisionBlock, Severity: "high"}, fmt.Errorf("coraza process body: %w", err)
		}
	} else if interruption != nil {
		interruptions = append(interruptions, interruption)
	}

	result := Result{Decision: DecisionAllow}
	hasDisruptive := false
	matchIndex := map[int]int{}
	for _, matched := range tx.MatchedRules() {
		rule := matched.Rule()
		if rule.ID() == 900000 {
			continue
		}
		severity := normalizeCorazaSeverity(rule.Severity())
		score := scoreForCorazaSeverity(severity)
		entry := MatchedRule{ID: rule.ID(), Message: firstNonEmpty(matched.Message(), matched.Data(), fmt.Sprintf("crs rule %d", rule.ID())), Source: "crs", Group: groupFromTags(rule.Tags()), Action: RuleActionLog, Severity: severity, Score: score}
		if matched.Disruptive() {
			entry.Action = RuleActionDeny
			hasDisruptive = true
		} else if severity == "info" || severity == "low" {
			score = 0
			entry.Score = 0
		}
		matchIndex[entry.ID] = len(result.Matches)
		result.Matches = append(result.Matches, entry)
		result.Score += score
		result.Severity = maxSeverity(result.Severity, severity)
	}
	if supplement != nil {
		supplementResult, err := supplement.Inspect(ctx, req)
		if err != nil && !cfg.FailOpen {
			return Result{Decision: DecisionBlock, Severity: "high"}, fmt.Errorf("supplemental detection: %w", err)
		}
		if err == nil {
			for _, local := range supplementResult.Matches {
				if index, ok := matchIndex[local.ID]; ok {
					merged := mergeSupplementedMatch(result.Matches[index], local, req)
					result.Score += merged.Score - result.Matches[index].Score
					result.Matches[index] = merged
					result.Severity = maxSeverity(result.Severity, merged.Severity)
					continue
				}
				if !shouldSupplementLocalOnlyMatch(local) {
					continue
				}
				local.Evidence = uniqueEvidence(append(local.Evidence, supplementalEvidenceForRule(local.ID, req)...))
				matchIndex[local.ID] = len(result.Matches)
				result.Matches = append(result.Matches, local)
				result.Score += local.Score
				result.Severity = maxSeverity(result.Severity, local.Severity)
			}
		}
	}
	hasDisruptive = false
	for _, match := range result.Matches {
		if match.Action == RuleActionDeny {
			hasDisruptive = true
			break
		}
	}
	sort.SliceStable(result.Matches, func(i, j int) bool {
		if result.Matches[i].Action != result.Matches[j].Action {
			return result.Matches[i].Action == RuleActionDeny
		}
		if result.Matches[i].Score != result.Matches[j].Score {
			return result.Matches[i].Score > result.Matches[j].Score
		}
		return result.Matches[i].ID < result.Matches[j].ID
	})
	for _, interruption := range interruptions {
		if interruption != nil {
			result.Decision = DecisionBlock
			break
		}
	}
	if result.Decision != DecisionBlock && hasDisruptive {
		result.Decision = DecisionBlock
	}
	return result, nil
}

func (e *CorazaEngine) Rules() []Rule {
	if e == nil || e.manager == nil {
		return nil
	}
	status := e.manager.Status()
	if status.RuleCount == 0 {
		return nil
	}
	return []Rule{{ID: 900000, Phase: 1, Group: "crs", Variable: "REQUEST", Operator: "coraza", Pattern: status.RulesDir, Action: RuleActionDeny, Message: "OWASP CRS via Coraza", Severity: "high", Score: status.InboundThreshold, Source: "crs", Enabled: status.Enabled && status.Loaded}}
}

func (e *CorazaEngine) EnableRule(int) error  { return nil }
func (e *CorazaEngine) DisableRule(int) error { return nil }

func buildCorazaWAF(cfg crs.Config, files []string) (coraza.WAF, error) {
	config := coraza.NewWAFConfig().WithRequestBodyAccess().WithRequestBodyLimit(int(cfg.RequestBodyLimit)).WithDirectives(baseCorazaDirectives(cfg))
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read coraza rule file %s: %w", file, err)
		}
		filtered := filterCorazaCompatibleDirectives(string(content))
		if strings.TrimSpace(filtered) == "" {
			continue
		}
		config = config.WithDirectives(filtered)
	}
	return coraza.NewWAF(config)
}

func baseCorazaDirectives(cfg crs.Config) string {
	return fmt.Sprintf(`SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecDefaultAction "phase:1,log,pass"
SecDefaultAction "phase:2,log,pass"
SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=%d,setvar:tx.executing_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"
`, cfg.ParanoiaLevel, cfg.ParanoiaLevel, cfg.InboundThreshold, cfg.OutboundThreshold)
}

func normalizeCorazaSeverity(severity corazatypes.RuleSeverity) string {
	switch severity.String() {
	case "emergency", "alert", "critical":
		return "critical"
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "notice":
		return "low"
	case "info", "debug":
		return "info"
	default:
		return "medium"
	}
}

func scoreForCorazaSeverity(severity string) int {
	switch severity {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func groupFromTags(tags []string) string {
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		switch {
		case strings.Contains(lower, "attack-sqli") || strings.Contains(lower, "sqli"):
			return "sqli"
		case strings.Contains(lower, "attack-xss") || strings.Contains(lower, "xss"):
			return "xss"
		case strings.Contains(lower, "protocol"):
			return "protocol"
		}
	}
	return "crs"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func mergeSupplementedMatch(base, local MatchedRule, req Request) MatchedRule {
	base.Evidence = uniqueEvidence(append(base.Evidence, local.Evidence...))
	base.Evidence = uniqueEvidence(append(base.Evidence, supplementalEvidenceForRule(local.ID, req)...))
	base.Group = firstNonEmpty(local.Group, base.Group)
	base.Score = local.Score
	base.Severity = firstNonEmpty(local.Severity, base.Severity)
	base.Action = local.Action
	if strings.TrimSpace(local.Message) != "" {
		base.Message = local.Message
	}
	return base
}

func shouldSupplementLocalOnlyMatch(match MatchedRule) bool {
	if match.Action != RuleActionDeny {
		return false
	}
	switch match.ID {
	case 906001, 909048, 910001, 910008, 910021, 910034:
		return true
	}
	for _, evidence := range match.Evidence {
		switch {
		case strings.HasPrefix(evidence, "ARGS:json."),
			strings.HasPrefix(evidence, "ARGS:graphql."),
			strings.HasPrefix(evidence, "ARGS:jwt."),
			strings.HasPrefix(evidence, "ARGS:request."):
			return true
		}
	}
	return false
}

func supplementalEvidenceForRule(ruleID int, req Request) []string {
	var evidence []string
	addArg := func(key string) {
		for _, value := range req.Args[key] {
			evidence = append(evidence, fmt.Sprintf("ARGS:%s=%s", key, truncateEvidence(value)))
		}
	}
	addFieldPrefix := func(prefix string) {
		for _, field := range req.ParsedRequest.Fields {
			if strings.HasPrefix(field.Variable, prefix) {
				evidence = append(evidence, fmt.Sprintf("%s=%s", field.Variable, truncateEvidence(field.NormalizedValue)))
			}
		}
	}
	switch ruleID {
	case 909002:
		addFieldPrefix("REQUEST_HEADERS:Transfer-Encoding")
		addFieldPrefix("REQUEST_HEADERS:Content-Length")
	case 909048:
		addFieldPrefix("META:request.content_length.count")
		if len(req.Args["request.content_length.count"]) > 0 {
			addArg("request.content_length.count")
		} else {
			for _, field := range req.ParsedRequest.Fields {
				if field.Variable == "META:request.content_length.count" {
					evidence = append(evidence, fmt.Sprintf("ARGS:request.content_length.count=%s", truncateEvidence(field.NormalizedValue)))
				}
			}
		}
	case 910001:
		addFieldPrefix("GRAPHQL:has_introspection")
		addFieldPrefix("GRAPHQL:has_alias_introspection")
		addArg("graphql.has_introspection")
		addArg("graphql.has_alias_introspection")
	case 910008:
		addFieldPrefix("GRAPHQL:depth")
		addArg("graphql.depth")
	case 910021:
		addFieldPrefix("JSON:__proto__")
		addFieldPrefix("JSON:prototype")
		addFieldPrefix("JSON:constructor")
	case 910030:
		addArg("jwt.header.alg")
		addArg("jwt.signature.present")
	case 910034:
		addArg("json.role")
	}
	return uniqueEvidence(evidence)
}

func filterCorazaCompatibleDirectives(content string) string {
	lines := strings.SplitAfter(content, "\n")
	var out strings.Builder
	for i := 0; i < len(lines); {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "SecRule ") {
			out.WriteString(line)
			i++
			continue
		}
		block := line
		for strings.HasSuffix(strings.TrimRight(block, "\r\n"), "\\") && i+1 < len(lines) {
			i++
			block += lines[i]
		}
		if !isCorazaUnsupportedRuleStart(trimmed) {
			out.WriteString(stripUnsupportedCorazaActions(block))
		}
		i++
	}
	return out.String()
}

func isCorazaUnsupportedRuleStart(line string) bool {
	line = strings.ToUpper(strings.TrimSpace(line))
	return strings.HasPrefix(line, "SECRULE GRAPHQL:") ||
		strings.HasPrefix(line, "SECRULE JWT:") ||
		strings.HasPrefix(line, "SECRULE JSON:") ||
		strings.HasPrefix(line, "SECRULE META:")
}

func stripUnsupportedCorazaActions(block string) string {
	scoreActionPattern := regexp.MustCompile(`,\s*score\s*:\s*'[^']*'|,\s*score\s*:\s*[^,\r\n"]+`)
	return scoreActionPattern.ReplaceAllString(block, "")
}

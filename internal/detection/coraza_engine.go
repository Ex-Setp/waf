package detection

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"aegis-waf/internal/crs"

	coraza "github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
)

type CorazaEngine struct {
	mu      sync.RWMutex
	manager *crs.Manager
	waf     coraza.WAF
	config  crs.Config
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
			e.mu.Unlock()
			return nil
		}
		return err
	}
	e.mu.Lock()
	e.config = cfg
	e.waf = waf
	e.mu.Unlock()
	return nil
}

func (e *CorazaEngine) Inspect(_ context.Context, req Request) (Result, error) {
	e.mu.RLock()
	waf := e.waf
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
		}
		result.Matches = append(result.Matches, entry)
		result.Score += score
		result.Severity = maxSeverity(result.Severity, severity)
	}
	for _, interruption := range interruptions {
		if interruption != nil {
			result.Decision = DecisionBlock
			break
		}
	}
	if result.Score >= cfg.InboundThreshold && len(result.Matches) > 0 {
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
		config = config.WithDirectivesFromFile(file)
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

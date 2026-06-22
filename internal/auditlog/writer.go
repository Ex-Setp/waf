package auditlog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegis-waf/internal/database"
	"aegis-waf/internal/gateway"
	"aegis-waf/internal/pipeline"

	"gorm.io/gorm"
)

const (
	defaultQueueSize     = 1024
	defaultBatchSize     = 64
	defaultFlushInterval = 100 * time.Millisecond
)

type Writer struct {
	db            *gorm.DB
	accessQueue   chan database.AccessLog
	attackQueue   chan database.AttackLog
	stop          chan struct{}
	done          chan struct{}
	stopOnce      sync.Once
	stopped       atomic.Bool
	droppedAccess atomic.Int64
	batchSize     int
	flushInterval time.Duration
}

type WriterStats struct {
	QueuedAccess  int
	QueuedAttack  int
	DroppedAccess int64
}

func NewWriter(db *gorm.DB) *Writer {
	return NewQueuedWriter(db, defaultQueueSize, defaultBatchSize, defaultFlushInterval)
}

func NewQueuedWriter(db *gorm.DB, queueSize, batchSize int, flushInterval time.Duration) *Writer {
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	if flushInterval <= 0 {
		flushInterval = defaultFlushInterval
	}
	writer := &Writer{db: db, accessQueue: make(chan database.AccessLog, queueSize), attackQueue: make(chan database.AttackLog, queueSize), stop: make(chan struct{}), done: make(chan struct{}), batchSize: batchSize, flushInterval: flushInterval}
	go writer.run()
	return writer
}

func (w *Writer) WriteAccess(_ context.Context, entry database.AccessLog) error {
	if w == nil || w.db == nil || w.stopped.Load() {
		return nil
	}
	select {
	case w.accessQueue <- entry:
	default:
		w.droppedAccess.Add(1)
	}
	return nil
}

func (w *Writer) WriteAttack(ctx context.Context, entry database.AttackLog) error {
	if w == nil || w.db == nil || w.stopped.Load() {
		return nil
	}
	select {
	case w.attackQueue <- entry:
		return nil
	default:
	}
	select {
	case w.attackQueue <- entry:
		return nil
	case <-ctx.Done():
		select {
		case w.attackQueue <- entry:
			return nil
		case <-w.stop:
			return nil
		}
	case <-w.stop:
		return nil
	}
}

func (w *Writer) Stop(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.stopOnce.Do(func() {
		w.stopped.Store(true)
		close(w.stop)
	})
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Writer) Stats() WriterStats {
	if w == nil {
		return WriterStats{}
	}
	return WriterStats{QueuedAccess: len(w.accessQueue), QueuedAttack: len(w.attackQueue), DroppedAccess: w.droppedAccess.Load()}
}

func (w *Writer) run() {
	defer close(w.done)
	if w == nil || w.db == nil {
		return
	}
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()
	accessBatch := make([]database.AccessLog, 0, w.batchSize)
	attackBatch := make([]database.AttackLog, 0, w.batchSize)
	flush := func() {
		if len(accessBatch) > 0 {
			_ = w.db.CreateInBatches(accessBatch, w.batchSize).Error
			accessBatch = accessBatch[:0]
		}
		if len(attackBatch) > 0 {
			_ = w.db.CreateInBatches(attackBatch, w.batchSize).Error
			attackBatch = attackBatch[:0]
		}
	}
	for {
		select {
		case entry := <-w.accessQueue:
			accessBatch = append(accessBatch, entry)
			if len(accessBatch) >= w.batchSize {
				flush()
			}
		case entry := <-w.attackQueue:
			attackBatch = append(attackBatch, entry)
			if len(attackBatch) >= w.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.stop:
			w.drain(&accessBatch, &attackBatch)
			flush()
			return
		}
	}
}

func (w *Writer) drain(accessBatch *[]database.AccessLog, attackBatch *[]database.AttackLog) {
	for {
		select {
		case entry := <-w.accessQueue:
			*accessBatch = append(*accessBatch, entry)
		case entry := <-w.attackQueue:
			*attackBatch = append(*attackBatch, entry)
		default:
			return
		}
	}
}

func AccessLogFrom(site *gateway.SiteRuntime, req pipeline.Request, status int, decision pipeline.Decision, upstream string, latency time.Duration, bytesIn int64) database.AccessLog {
	entry := database.AccessLog{RequestID: req.ID, Host: req.Host, SourceIP: req.RemoteIP.String(), Method: req.Method, Path: req.Path, Status: status, Decision: string(decision), Upstream: upstream, LatencyMS: float64(latency) / float64(time.Millisecond), BytesIn: bytesIn}
	if req.Headers != nil {
		entry.UserAgent = req.Headers.Get("User-Agent")
	}
	if site != nil {
		entry.SiteID = site.ID
		entry.SiteName = site.Name
	}
	if idx := strings.Index(entry.Path, "?"); idx >= 0 {
		entry.Query = strings.TrimPrefix(entry.Path[idx+1:], "?")
		entry.Path = entry.Path[:idx]
	}
	return entry
}

func AttackLogFrom(site *gateway.SiteRuntime, req pipeline.Request, result pipeline.Result, status int, latency time.Duration) database.AttackLog {
	action := "block"
	if result.Decision != pipeline.DecisionBlock {
		action = "observe"
	}
	finalAction := string(result.FinalAction)
	if finalAction == "" {
		finalAction = action
	}
	entry := database.AttackLog{RequestID: req.ID, SourceIP: req.RemoteIP.String(), Method: req.Method, Path: req.Path, AttackType: attackType(result), Severity: detectionSeverity(result), Action: action, FinalAction: finalAction, Stage: defaultString(result.BlockedByStage, "detection"), RuleID: firstRuleID(result), RuleMessage: firstRuleMessage(result), Score: detectionScore(result), ScoreBreakdown: scoreBreakdown(result), ExplanationJSON: explanationJSON(site, req, result, finalAction), OperatorSuggestion: operatorSuggestionsJSON(site, req, result, finalAction), StatusCode: status, LatencyMS: float64(latency) / float64(time.Millisecond), PayloadSnippet: requestSnippet(req, 512)}
	if site != nil {
		entry.SiteID = site.ID
		entry.SiteName = site.Name
	}
	if entry.Stage == "" {
		entry.Stage = "waf"
	}
	if entry.RuleID == "" {
		entry.RuleID = entry.Stage
	}
	return entry
}

func explanationJSON(site *gateway.SiteRuntime, req pipeline.Request, result pipeline.Result, finalAction string) string {
	type sitePolicyInfo struct {
		SiteID              uint     `json:"siteId"`
		SiteName            string   `json:"siteName"`
		PolicyMode          string   `json:"policyMode"`
		BlockScoreThreshold int      `json:"blockScoreThreshold"`
		RuleGroups          []string `json:"ruleGroups,omitempty"`
	}
	type matchedRuleInfo struct {
		ID       int    `json:"id"`
		Source   string `json:"source"`
		Group    string `json:"group"`
		Severity string `json:"severity"`
		Score    int    `json:"score"`
		Action   string `json:"action"`
		Message  string `json:"message"`
	}
	type requestVariableInfo struct {
		Variable        string   `json:"variable"`
		Source          string   `json:"source"`
		RawValue        string   `json:"rawValue"`
		NormalizedValue string   `json:"normalizedValue"`
		DecodeSteps     []string `json:"decodeSteps,omitempty"`
	}
	type normalizationStepInfo struct {
		Variable string   `json:"variable"`
		Steps    []string `json:"steps"`
	}
	type decisionInfo struct {
		Status string `json:"status"`
		Reason string `json:"reason,omitempty"`
	}
	type explanation struct {
		SitePolicy         sitePolicyInfo          `json:"sitePolicy"`
		MatchedRules       []matchedRuleInfo       `json:"matchedRules"`
		ScoreBreakdown     json.RawMessage         `json:"scoreBreakdown,omitempty"`
		RequestVariables   []requestVariableInfo   `json:"requestVariables"`
		NormalizationSteps []normalizationStepInfo `json:"normalizationSteps"`
		WhitelistDecision  decisionInfo            `json:"whitelistDecision"`
		CCBotDecision      decisionInfo            `json:"ccBotDecision"`
		SemanticDecision   decisionInfo            `json:"semanticDecision"`
		FinalAction        string                  `json:"finalAction"`
		Reason             string                  `json:"reason"`
	}
	exp := explanation{MatchedRules: []matchedRuleInfo{}, RequestVariables: []requestVariableInfo{}, NormalizationSteps: []normalizationStepInfo{}, WhitelistDecision: decisionInfo{Status: "not_matched"}, CCBotDecision: decisionInfo{Status: "not_matched"}, SemanticDecision: decisionInfo{Status: "not_matched"}, FinalAction: finalAction, Reason: result.Reason}
	if site != nil {
		exp.SitePolicy = sitePolicyInfo{SiteID: site.ID, SiteName: site.Name, PolicyMode: site.PolicyMode, BlockScoreThreshold: site.BlockScoreThreshold, RuleGroups: site.RuleGroups}
	}
	for _, match := range result.Detection.Matches {
		exp.MatchedRules = append(exp.MatchedRules, matchedRuleInfo{ID: match.ID, Source: match.Source, Group: match.Group, Severity: match.Severity, Score: match.Score, Action: string(match.Action), Message: match.Message})
		if strings.HasPrefix(match.Source, "cc:") || strings.EqualFold(match.Group, "cc") || strings.Contains(strings.ToLower(match.Message), "policy=") {
			exp.CCBotDecision = decisionInfo{Status: finalAction, Reason: match.Message}
		}
	}
	for _, match := range result.Semantic.Matches {
		exp.MatchedRules = append(exp.MatchedRules, matchedRuleInfo{ID: match.ID, Source: match.Source, Group: defaultString(match.Group, "semantic"), Severity: match.Severity, Score: match.Score, Action: string(match.Action), Message: match.Message})
		exp.SemanticDecision = decisionInfo{Status: finalAction, Reason: match.Message}
	}
	if strings.EqualFold(result.BlockedByStage, "accesscontrol") {
		exp.WhitelistDecision = decisionInfo{Status: "blocked", Reason: result.Reason}
	}
	if sb := scoreBreakdown(result); strings.TrimSpace(sb) != "" {
		exp.ScoreBreakdown = json.RawMessage(sb)
	}
	for _, field := range req.ParsedRequest.Fields {
		steps := make([]string, 0, len(field.DecodeSteps))
		for _, step := range field.DecodeSteps {
			steps = append(steps, step.Stage)
		}
		rawValue := field.RawValue
		normalizedValue := field.NormalizedValue
		if isSensitiveVariable(field.Variable) {
			rawValue = "[REDACTED]"
			normalizedValue = "[REDACTED]"
		}
		exp.RequestVariables = append(exp.RequestVariables, requestVariableInfo{Variable: field.Variable, Source: field.Source, RawValue: rawValue, NormalizedValue: normalizedValue, DecodeSteps: steps})
		if len(steps) > 0 {
			exp.NormalizationSteps = append(exp.NormalizationSteps, normalizationStepInfo{Variable: field.Variable, Steps: steps})
		}
		if len(exp.RequestVariables) >= 20 {
			break
		}
	}
	data, err := json.Marshal(exp)
	if err != nil {
		return ""
	}
	return string(data)
}

func operatorSuggestionsJSON(site *gateway.SiteRuntime, req pipeline.Request, result pipeline.Result, finalAction string) string {
	type suggestion struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Target string `json:"target"`
		Reason string `json:"reason"`
		Action string `json:"action"`
	}
	suggestions := []suggestion{}
	pathValue := strings.Split(req.Path, "?")[0]
	if finalAction == "block" || finalAction == "observe" {
		suggestions = append(suggestions, suggestion{Type: "whitelist", Title: "误报时按路径加白", Target: pathValue, Reason: "同站点同路径业务请求如确认安全，可创建 URL/参数白名单", Action: "create_whitelist"})
	}
	if result.ScoreThreshold > 0 && detectionScore(result) >= result.ScoreThreshold {
		suggestions = append(suggestions, suggestion{Type: "site-policy", Title: "复核站点异常分阈值", Target: siteName(site), Reason: fmt.Sprintf("当前分数 %d 达到阈值 %d", detectionScore(result), result.ScoreThreshold), Action: "open_site_policy"})
	}
	for _, match := range result.Detection.Matches {
		if match.Group != "" {
			suggestions = append(suggestions, suggestion{Type: "rule-group", Title: "复核规则组", Target: match.Group, Reason: "可在规则管理中查看命中规则组和单条规则详情", Action: "open_rule_group"})
			break
		}
	}
	if strings.EqualFold(result.BlockedByStage, "cc") || strings.Contains(strings.ToLower(result.Reason), "cc") {
		suggestions = append(suggestions, suggestion{Type: "cc-bot", Title: "查看 CC/Bot 策略与封禁", Target: req.RemoteIP.String(), Reason: "该事件由 CC/Bot 策略触发，可解除封禁或调整动作链", Action: "open_cc_bot"})
	}
	if len(result.Semantic.Matches) > 0 {
		suggestions = append(suggestions, suggestion{Type: "semantic", Title: "复核语义指纹", Target: result.Semantic.Matches[0].Group, Reason: "语义命中可观察、回滚或升级规则", Action: "open_semantic_fingerprint"})
	}
	data, err := json.Marshal(suggestions)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func isSensitiveVariable(variable string) bool {
	variable = strings.ToLower(strings.TrimSpace(variable))
	parts := strings.FieldsFunc(variable, func(r rune) bool { return r == ':' || r == '.' || r == '-' || r == '_' })
	for _, part := range parts {
		switch part {
		case "password", "passwd", "pwd", "secret", "token", "authorization", "cookie", "api", "key":
			return true
		}
	}
	return false
}

func siteName(site *gateway.SiteRuntime) string {
	if site == nil {
		return ""
	}
	return site.Name
}

func scoreBreakdown(result pipeline.Result) string {
	type ruleScore struct {
		ID    int    `json:"id"`
		Group string `json:"group"`
		Score int    `json:"score"`
	}
	breakdown := struct {
		TotalScore int         `json:"totalScore"`
		Threshold  int         `json:"threshold"`
		Rules      []ruleScore `json:"rules"`
	}{TotalScore: detectionScore(result), Threshold: result.ScoreThreshold, Rules: make([]ruleScore, 0, len(result.Detection.Matches))}
	for _, match := range result.Detection.Matches {
		breakdown.Rules = append(breakdown.Rules, ruleScore{ID: match.ID, Group: match.Group, Score: match.Score})
	}
	data, err := json.Marshal(breakdown)
	if err != nil {
		return ""
	}
	return string(data)
}

func attackType(result pipeline.Result) string {
	if len(result.Detection.Matches) > 0 {
		return defaultString(result.Detection.Matches[0].Group, "detection")
	}
	if len(result.Semantic.Matches) > 0 {
		return defaultString(result.Semantic.Matches[0].Group, "semantic")
	}
	return defaultString(result.BlockedByStage, "detection")
}

func firstRuleID(result pipeline.Result) string {
	if len(result.Detection.Matches) > 0 {
		return fmt.Sprintf("%d", result.Detection.Matches[0].ID)
	}
	if len(result.Semantic.Matches) > 0 {
		return fmt.Sprintf("%d", result.Semantic.Matches[0].ID)
	}
	return ""
}

func firstRuleMessage(result pipeline.Result) string {
	if len(result.Detection.Matches) > 0 && strings.TrimSpace(result.Detection.Matches[0].Message) != "" {
		return result.Detection.Matches[0].Message
	}
	if len(result.Semantic.Matches) > 0 && strings.TrimSpace(result.Semantic.Matches[0].Message) != "" {
		return result.Semantic.Matches[0].Message
	}
	return result.Reason
}

func detectionScore(result pipeline.Result) int {
	if result.Detection.Score > 0 {
		return result.Detection.Score
	}
	return result.Semantic.Score
}

func detectionSeverity(result pipeline.Result) string {
	if result.Detection.Severity != "" {
		return result.Detection.Severity
	}
	if result.Semantic.Severity != "" {
		return result.Semantic.Severity
	}
	return "high"
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func requestSnippet(req pipeline.Request, limit int) string {
	type parserField struct {
		Variable        string   `json:"variable"`
		Source          string   `json:"source"`
		RawValue        string   `json:"rawValue"`
		NormalizedValue string   `json:"normalizedValue"`
		DecodeSteps     []string `json:"decodeSteps,omitempty"`
	}
	type parserExplanation struct {
		MatchedVariable string        `json:"matchedVariable,omitempty"`
		NormalizedPath  string        `json:"normalizedPath,omitempty"`
		Fields          []parserField `json:"fields,omitempty"`
		ParseErrors     []string      `json:"parseErrors,omitempty"`
	}
	type snippetExplanation struct {
		RawRequest        string            `json:"rawRequest,omitempty"`
		NormalizedRequest parserExplanation `json:"normalizedRequest"`
	}
	if len(req.ParsedRequest.Fields) > 0 || len(req.ParsedRequest.ParseErrors) > 0 {
		var builder strings.Builder
		method := defaultString(req.Method, "GET")
		path := defaultString(req.Path, "/")
		builder.WriteString(method)
		builder.WriteString(" ")
		builder.WriteString(path)
		builder.WriteString(" HTTP/1.1\n")
		if strings.TrimSpace(req.Host) != "" {
			builder.WriteString("Host: ")
			builder.WriteString(req.Host)
			builder.WriteString("\n")
		}
		if req.Headers != nil && strings.TrimSpace(req.Headers.Get("User-Agent")) != "" {
			builder.WriteString("User-Agent: ")
			builder.WriteString(req.Headers.Get("User-Agent"))
			builder.WriteString("\n")
		}
		explanation := parserExplanation{NormalizedPath: req.ParsedRequest.NormalizedPath, Fields: make([]parserField, 0, 5)}
		for _, field := range req.ParsedRequest.Fields {
			if len(explanation.Fields) >= 5 {
				break
			}
			steps := make([]string, 0, len(field.DecodeSteps))
			for _, step := range field.DecodeSteps {
				steps = append(steps, step.Stage)
			}
			if explanation.MatchedVariable == "" && field.Variable != "" {
				explanation.MatchedVariable = field.Variable
			}
			explanation.Fields = append(explanation.Fields, parserField{Variable: field.Variable, Source: field.Source, RawValue: field.RawValue, NormalizedValue: field.NormalizedValue, DecodeSteps: steps})
		}
		for _, parseErr := range req.ParsedRequest.ParseErrors {
			explanation.ParseErrors = append(explanation.ParseErrors, parseErr.Source+": "+parseErr.Message)
		}
		if data, err := json.Marshal(snippetExplanation{RawRequest: builder.String(), NormalizedRequest: explanation}); err == nil {
			return snippet(string(data), limit*4)
		}
	}
	var builder strings.Builder
	method := defaultString(req.Method, "GET")
	path := defaultString(req.Path, "/")
	builder.WriteString(method)
	builder.WriteString(" ")
	builder.WriteString(path)
	builder.WriteString(" HTTP/1.1\n")
	if strings.TrimSpace(req.Host) != "" {
		builder.WriteString("Host: ")
		builder.WriteString(req.Host)
		builder.WriteString("\n")
	}
	if req.Headers != nil && strings.TrimSpace(req.Headers.Get("User-Agent")) != "" {
		builder.WriteString("User-Agent: ")
		builder.WriteString(req.Headers.Get("User-Agent"))
		builder.WriteString("\n")
	}
	if strings.TrimSpace(req.Body) != "" {
		builder.WriteString("\n")
		builder.WriteString(req.Body)
	}
	return snippet(builder.String(), limit)
}

func snippet(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

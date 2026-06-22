package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"aegis-waf/internal/dataplane"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/featureloop"
	"aegis-waf/internal/normalizer"
	"aegis-waf/internal/requestparser"
)

const (
	StageDataplane   = "dataplane"
	StageDetection   = "detection"
	StageSemantic    = "semantic"
	StageFeatureLoop = "featureloop"
	StageTotal       = "total"
)

type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionObserve Decision = "observe"
	DecisionBlock   Decision = "block"
)

type Config struct {
	FailOpen bool
}

type Pipeline struct {
	cfg Config

	dataplane   dataplane.Engine
	detection   detection.Engine
	semantic    detection.Engine
	featureLoop FeatureLoop
	now         func() time.Time
}

type Option func(*Pipeline)

func WithDataplane(engine dataplane.Engine) Option {
	return func(p *Pipeline) { p.dataplane = engine }
}

func WithDetection(engine detection.Engine) Option {
	return func(p *Pipeline) { p.detection = engine }
}

func WithSemantic(engine detection.Engine) Option {
	return func(p *Pipeline) { p.semantic = engine }
}

func WithFeatureLoop(loop FeatureLoop) Option {
	return func(p *Pipeline) { p.featureLoop = loop }
}

func WithClock(now func() time.Time) Option {
	return func(p *Pipeline) {
		if now != nil {
			p.now = now
		}
	}
}

func New(cfg Config, options ...Option) *Pipeline {
	p := &Pipeline{cfg: cfg, now: time.Now}
	for _, option := range options {
		option(p)
	}
	return p
}

type Request struct {
	ID                  string
	Method              string
	Path                string
	Host                string
	RemoteIP            net.IP
	Headers             http.Header
	Args                map[string][]string
	Body                string
	BlockScoreThreshold int
	ForceSemantic       bool
	DisabledRuleIDs     map[int]bool
	EnabledRuleGroups   map[string]bool
	Timestamp           time.Time
	ParsedRequest       requestparser.ParsedRequest
}

type Result struct {
	Decision       Decision
	FinalAction    Decision
	Reason         string
	Errors         []error
	StageMetrics   []StageMetric
	Dataplane      dataplane.Result
	Detection      detection.Result
	Semantic       detection.Result
	FeatureLoop    FeatureResult
	ScoreThreshold int
	ProcessedAt    time.Time
	TotalDuration  time.Duration
	BlockedByStage string
}

type StageMetric struct {
	Stage    string
	Duration time.Duration
	Error    string
	Decision Decision
}

type FeatureInput struct {
	Request   Request
	Decision  Decision
	Reason    string
	Detection detection.Result
	Semantic  detection.Result
}

type FeatureResult struct {
	Rules    []featureloop.GeneratedRule
	Rollback featureloop.RollbackResult
	Observed bool
	Decision Decision
	Reason   string
}

type FeatureLoop interface {
	Evaluate(context.Context, FeatureInput) (FeatureResult, error)
}

func (p *Pipeline) Process(ctx context.Context, req Request) (result Result, err error) {
	if p.now == nil {
		p.now = time.Now
	}
	started := p.now()
	if req.Timestamp.IsZero() {
		req.Timestamp = started
	}

	result = Result{Decision: DecisionAllow, FinalAction: DecisionAllow, Reason: "allowed", ProcessedAt: started}
	defer func() {
		if result.FinalAction == "" {
			result.FinalAction = result.Decision
		}
		result.TotalDuration = time.Since(started)
		result.StageMetrics = append(result.StageMetrics, StageMetric{Stage: StageTotal, Duration: result.TotalDuration, Decision: result.Decision})
	}()

	if p.dataplane != nil {
		stageStarted := time.Now()
		dpResult, err := p.dataplane.Evaluate(ctx, toDataplaneRequest(req))
		result.Dataplane = dpResult
		result.StageMetrics = append(result.StageMetrics, StageMetric{Stage: StageDataplane, Duration: time.Since(stageStarted), Error: errorString(err), Decision: fromDataplaneDecision(dpResult.Decision)})
		if err != nil {
			if final, done := p.handleStageError(&result, StageDataplane, err); done {
				return final, err
			}
		}
		if dpResult.Decision == dataplane.DecisionBlock {
			result.Decision = DecisionBlock
			result.FinalAction = DecisionBlock
			result.Reason = defaultReason(dpResult.Reason, "dataplane blocked request")
			result.BlockedByStage = StageDataplane
			return result, nil
		}
	}

	if p.detection != nil {
		stageStarted := time.Now()
		detectionResult, err := p.detection.Inspect(ctx, toDetectionRequest(req))
		detectionResult = filterDisabledDetectionMatches(detectionResult, req.DisabledRuleIDs)
		result.Detection = detectionResult
		result.StageMetrics = append(result.StageMetrics, StageMetric{Stage: StageDetection, Duration: time.Since(stageStarted), Error: errorString(err), Decision: fromDetectionDecision(detectionResult.Decision)})
		if err != nil {
			if final, done := p.handleStageError(&result, StageDetection, err); done {
				return final, err
			}
		}
		if detectionResult.Decision == detection.DecisionBlock {
			threshold := blockScoreThreshold(req)
			result.ScoreThreshold = threshold
			if detectionResult.Score >= threshold {
				result.Decision = DecisionBlock
				result.FinalAction = DecisionBlock
				result.Reason = fmt.Sprintf("detection score %d reached threshold %d", detectionResult.Score, threshold)
				result.BlockedByStage = StageDetection
				return result, nil
			}
			result.Decision = DecisionObserve
			result.FinalAction = DecisionObserve
			result.Reason = fmt.Sprintf("detection observed score %d below threshold %d", detectionResult.Score, threshold)
		}
	}

	if p.semantic != nil && shouldRunSemantic(req, result.Detection, result.ScoreThreshold) {
		stageStarted := time.Now()
		semanticResult, err := p.semantic.Inspect(ctx, toDetectionRequest(req))
		semanticResult = filterDisabledDetectionMatches(semanticResult, req.DisabledRuleIDs)
		result.Semantic = semanticResult
		result.StageMetrics = append(result.StageMetrics, StageMetric{Stage: StageSemantic, Duration: time.Since(stageStarted), Error: errorString(err), Decision: fromDetectionDecision(semanticResult.Decision)})
		if err != nil {
			if final, done := p.handleStageError(&result, StageSemantic, err); done {
				return final, err
			}
		}
		if semanticResult.Decision == detection.DecisionBlock {
			result.Decision = DecisionBlock
			result.FinalAction = DecisionBlock
			result.Reason = "semantic analysis blocked request"
			result.BlockedByStage = StageSemantic
		}
	}

	if p.featureLoop != nil {
		stageStarted := time.Now()
		featureResult, err := p.featureLoop.Evaluate(ctx, FeatureInput{Request: req, Decision: result.Decision, Reason: result.Reason, Detection: result.Detection, Semantic: result.Semantic})
		result.FeatureLoop = featureResult
		result.StageMetrics = append(result.StageMetrics, StageMetric{Stage: StageFeatureLoop, Duration: time.Since(stageStarted), Error: errorString(err), Decision: featureResult.Decision})
		if err != nil {
			if final, done := p.handleStageError(&result, StageFeatureLoop, err); done {
				return final, err
			}
		}
		if featureResult.Decision == DecisionBlock {
			result.Decision = DecisionBlock
			result.FinalAction = DecisionBlock
			result.Reason = defaultReason(featureResult.Reason, "feature loop blocked request")
			result.BlockedByStage = StageFeatureLoop
		}
	}

	return result, nil
}

func (p *Pipeline) handleStageError(result *Result, stage string, err error) (Result, bool) {
	result.Errors = append(result.Errors, fmt.Errorf("%s: %w", stage, err))
	if p.cfg.FailOpen {
		if result.Decision == "" {
			result.Decision = DecisionAllow
		}
		if result.FinalAction == "" {
			result.FinalAction = result.Decision
		}
		if result.Reason == "" || result.Reason == "allowed" {
			result.Reason = "allowed by fail-open"
		}
		return *result, false
	}
	result.Decision = DecisionBlock
	result.FinalAction = DecisionBlock
	result.Reason = fmt.Sprintf("%s error: fail-closed", stage)
	result.BlockedByStage = stage
	return *result, true
}

func toDataplaneRequest(req Request) dataplane.RequestMeta {
	return dataplane.RequestMeta{ID: req.ID, Method: req.Method, Path: req.Path, Host: req.Host, RemoteIP: req.RemoteIP, Headers: map[string][]string(req.Headers), Timestamp: req.Timestamp}
}

func toDetectionRequest(req Request) detection.Request {
	normalized := normalizer.RequestCopy(normalizer.Request{Method: req.Method, URI: req.Path, Headers: req.Headers, Body: req.Body, Args: req.Args})
	return detection.Request{Method: normalized.Method, URI: normalized.URI, Headers: normalized.Headers, Body: normalized.Body, Args: normalized.Args, EnabledRuleGroups: req.EnabledRuleGroups}
}

func fromDataplaneDecision(decision dataplane.Decision) Decision {
	switch decision {
	case dataplane.DecisionBlock:
		return DecisionBlock
	case dataplane.DecisionAllow:
		return DecisionAllow
	default:
		return ""
	}
}

func fromDetectionDecision(decision detection.Decision) Decision {
	switch decision {
	case detection.DecisionBlock:
		return DecisionBlock
	case detection.DecisionAllow:
		return DecisionAllow
	default:
		return ""
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func defaultReason(reason, fallback string) string {
	if reason != "" {
		return reason
	}
	return fallback
}

func blockScoreThreshold(req Request) int {
	if req.BlockScoreThreshold > 0 {
		return req.BlockScoreThreshold
	}
	return 5
}

func shouldRunSemantic(req Request, detectionResult detection.Result, threshold int) bool {
	if isStaticAsset(req.Path) {
		return false
	}
	if req.ForceSemantic {
		return true
	}
	if threshold <= 0 {
		threshold = blockScoreThreshold(req)
	}
	if len(detectionResult.Matches) > 0 && detectionResult.Score < threshold {
		return true
	}
	normalized := toDetectionRequest(req)
	if containsHighRiskToken(normalized.URI) || containsHighRiskToken(normalized.Body) {
		return true
	}
	for key, values := range normalized.Args {
		if containsHighRiskToken(key) {
			return true
		}
		for _, value := range values {
			if containsHighRiskToken(value) {
				return true
			}
		}
	}
	return isHighRiskPath(normalized.URI)
}

func isStaticAsset(uri string) bool {
	path := strings.ToLower(strings.SplitN(uri, "?", 2)[0])
	staticExts := []string{".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".avif"}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/static/")
}

func isHighRiskPath(uri string) bool {
	path := strings.ToLower(strings.SplitN(uri, "?", 2)[0])
	return path == "/login" || path == "/search" || strings.HasPrefix(path, "/api/")
}

func containsHighRiskToken(value string) bool {
	text := strings.ToLower(value)
	tokens := []string{"union select", "<script", "javascript:", "onerror=", "onload=", "select ", "insert ", "update ", "delete ", "drop ", " or 1=1", "../"}
	for _, token := range tokens {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func Errors(result Result) error {
	return errors.Join(result.Errors...)
}

func filterDisabledDetectionMatches(result detection.Result, disabled map[int]bool) detection.Result {
	if len(disabled) == 0 || len(result.Matches) == 0 {
		return result
	}
	filtered := result.Matches[:0]
	score := 0
	severity := ""
	decision := detection.DecisionAllow
	for _, match := range result.Matches {
		if disabled[match.ID] {
			continue
		}
		filtered = append(filtered, match)
		score += match.Score
		severity = maxPipelineSeverity(severity, match.Severity)
		if match.Action == detection.RuleActionDeny {
			decision = detection.DecisionBlock
		}
	}
	result.Matches = filtered
	result.Score = score
	result.Severity = severity
	result.Decision = decision
	return result
}
func maxPipelineSeverity(a, b string) string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

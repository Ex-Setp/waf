package pipeline

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"aegis-waf/internal/dataplane"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/featureloop"
)

type dataplaneStub struct {
	result dataplane.Result
	err    error
	calls  []string
	order  *[]string
}

func (s *dataplaneStub) Start(context.Context) error { return nil }
func (s *dataplaneStub) Stop(context.Context) error  { return nil }
func (s *dataplaneStub) Evaluate(context.Context, dataplane.RequestMeta) (dataplane.Result, error) {
	*s.order = append(*s.order, StageDataplane)
	s.calls = append(s.calls, StageDataplane)
	return s.result, s.err
}

type detectionStub struct {
	stage    string
	result   detection.Result
	err      error
	order    *[]string
	requests []detection.Request
}

func (s *detectionStub) Start(context.Context) error  { return nil }
func (s *detectionStub) Stop(context.Context) error   { return nil }
func (s *detectionStub) Reload(context.Context) error { return nil }
func (s *detectionStub) Inspect(_ context.Context, req detection.Request) (detection.Result, error) {
	*s.order = append(*s.order, s.stage)
	s.requests = append(s.requests, req)
	return s.result, s.err
}
func (s *detectionStub) Rules() []detection.Rule { return nil }
func (s *detectionStub) EnableRule(int) error    { return nil }
func (s *detectionStub) DisableRule(int) error   { return nil }

type featureLoopStub struct {
	result FeatureResult
	err    error
	inputs []FeatureInput
	order  *[]string
}

func (s *featureLoopStub) Evaluate(_ context.Context, input FeatureInput) (FeatureResult, error) {
	*s.order = append(*s.order, StageFeatureLoop)
	s.inputs = append(s.inputs, input)
	return s.result, s.err
}

func TestProcessRunsFourStagesInOrder(t *testing.T) {
	var order []string
	fl := &featureLoopStub{order: &order, result: FeatureResult{Observed: true}}
	p := New(Config{FailOpen: true},
		WithDataplane(&dataplaneStub{order: &order, result: dataplane.Result{Decision: dataplane.DecisionAllow}}),
		WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}),
		WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{Decision: detection.DecisionAllow}}),
		WithFeatureLoop(fl),
	)

	result, err := p.Process(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	wantOrder := []string{StageDataplane, StageDetection, StageSemantic, StageFeatureLoop}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("stage order = %v, want %v", order, wantOrder)
	}
	if result.Decision != DecisionAllow {
		t.Fatalf("decision = %s, want allow", result.Decision)
	}
	assertMetricStages(t, result, []string{StageDataplane, StageDetection, StageSemantic, StageFeatureLoop, StageTotal})
	if len(fl.inputs) != 1 || fl.inputs[0].Decision != DecisionAllow {
		t.Fatalf("feature loop input = %#v, want allow decision", fl.inputs)
	}
}

func TestDataplaneBlockShortCircuits(t *testing.T) {
	var order []string
	p := New(Config{FailOpen: true},
		WithDataplane(&dataplaneStub{order: &order, result: dataplane.Result{Decision: dataplane.DecisionBlock, Reason: "xdp-hit"}}),
		WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}),
	)

	result, err := p.Process(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if result.Decision != DecisionBlock || result.BlockedByStage != StageDataplane || result.Reason != "xdp-hit" {
		t.Fatalf("unexpected block result: %#v", result)
	}
	if !reflect.DeepEqual(order, []string{StageDataplane}) {
		t.Fatalf("order = %v, want only dataplane", order)
	}
}

func TestDetectionBlockShortCircuitsBeforeSemantic(t *testing.T) {
	var order []string
	p := New(Config{FailOpen: true},
		WithDataplane(&dataplaneStub{order: &order, result: dataplane.Result{Decision: dataplane.DecisionAllow}}),
		WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionBlock, Score: 7, Severity: "high"}}),
		WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{Decision: detection.DecisionAllow}}),
	)

	result, err := p.Process(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if result.Decision != DecisionBlock || result.BlockedByStage != StageDetection {
		t.Fatalf("unexpected detection block: %#v", result)
	}
	if !reflect.DeepEqual(order, []string{StageDataplane, StageDetection}) {
		t.Fatalf("order = %v, want dataplane+detection", order)
	}
}

func TestDetectionScoreBelowThresholdObservesAndContinues(t *testing.T) {
	var order []string
	p := New(Config{FailOpen: true},
		WithDataplane(&dataplaneStub{order: &order, result: dataplane.Result{Decision: dataplane.DecisionAllow}}),
		WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionBlock, Score: 3, Severity: "low", Matches: []detection.MatchedRule{{ID: 100100, Score: 3, Severity: "low"}}}}),
		WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{Decision: detection.DecisionAllow}}),
	)

	req := sampleRequest()
	req.Path = "/"
	req.Body = ""
	req.Args = map[string][]string{"q": {"lowprobe"}}
	req.BlockScoreThreshold = 5
	result, err := p.Process(context.Background(), req)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if result.Decision != DecisionObserve || result.FinalAction != DecisionObserve || result.ScoreThreshold != 5 || result.Detection.Score != 3 {
		t.Fatalf("expected low score observe, got %#v", result)
	}
	if !reflect.DeepEqual(order, []string{StageDataplane, StageDetection, StageSemantic}) {
		t.Fatalf("order = %v, want dataplane+detection+semantic", order)
	}
}

func TestT137DetectionScoreSetsFinalAction(t *testing.T) {
	tests := []struct {
		name         string
		score        int
		wantDecision Decision
		wantAction   Decision
	}{
		{name: "below threshold observes", score: 4, wantDecision: DecisionObserve, wantAction: DecisionObserve},
		{name: "at or above threshold blocks", score: 8, wantDecision: DecisionBlock, wantAction: DecisionBlock},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			p := New(Config{FailOpen: true},
				WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{
					Decision: detection.DecisionBlock,
					Score:    tc.score,
					Severity: "high",
					Matches:  []detection.MatchedRule{{ID: 100100, Score: tc.score, Severity: "high"}},
				}}),
			)

			req := sampleRequest()
			req.BlockScoreThreshold = 5
			result, err := p.Process(context.Background(), req)
			if err != nil {
				t.Fatalf("Process returned error: %v", err)
			}
			if result.Decision != tc.wantDecision || result.FinalAction != tc.wantAction {
				t.Fatalf("decision/action = %s/%s, want %s/%s; result=%#v", result.Decision, result.FinalAction, tc.wantDecision, tc.wantAction, result)
			}
		})
	}
}

func TestPipelinePassesEnabledRuleGroupsToDetection(t *testing.T) {
	var order []string
	det := &detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}
	p := New(Config{FailOpen: true}, WithDetection(det))

	req := sampleRequest()
	req.EnabledRuleGroups = map[string]bool{"xss": true}
	if _, err := p.Process(context.Background(), req); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if len(det.requests) != 1 || !det.requests[0].EnabledRuleGroups["xss"] {
		t.Fatalf("detection request missing enabled rule groups: %+v", det.requests)
	}
}

func TestSemanticRunsOnlyForSuspiciousTraffic(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		want []string
	}{
		{name: "static asset skips semantic", req: Request{Method: http.MethodGet, Path: "/assets/app.js"}, want: []string{StageDetection}},
		{name: "plain request skips semantic", req: Request{Method: http.MethodGet, Path: "/"}, want: []string{StageDetection}},
		{name: "loose policy skips semantic token", req: Request{Method: http.MethodGet, Path: "/", PolicyMode: "loose", Args: map[string][]string{"q": {"union select user"}}}, want: []string{StageDetection}},
		{name: "loose policy skips forced semantic", req: Request{Method: http.MethodGet, Path: "/api/users", PolicyMode: "loose", ForceSemantic: true}, want: []string{StageDetection}},
		{name: "sql token triggers semantic", req: Request{Method: http.MethodGet, Path: "/", Args: map[string][]string{"q": {"union select user"}}}, want: []string{StageDetection, StageSemantic}},
		{name: "high risk path triggers semantic", req: Request{Method: http.MethodGet, Path: "/login"}, want: []string{StageDetection, StageSemantic}},
		{name: "force semantic triggers semantic", req: Request{Method: http.MethodGet, Path: "/", ForceSemantic: true}, want: []string{StageDetection, StageSemantic}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			p := New(Config{FailOpen: true},
				WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}),
				WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{Decision: detection.DecisionAllow}}),
			)
			if _, err := p.Process(context.Background(), tc.req); err != nil {
				t.Fatalf("Process returned error: %v", err)
			}
			if !reflect.DeepEqual(order, tc.want) {
				t.Fatalf("order=%v, want %v", order, tc.want)
			}
		})
	}
}

func TestSemanticAndFeatureLoopHooks(t *testing.T) {
	var order []string
	fl := &featureLoopStub{order: &order, result: FeatureResult{Observed: true, Rules: []featureloop.GeneratedRule{{RuleID: 1001}}}}
	p := New(Config{FailOpen: true},
		WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{Decision: detection.DecisionAllow, Matches: []detection.MatchedRule{{ID: detection.SemanticSQLTaintRuleID}}}}),
		WithFeatureLoop(fl),
	)

	result, err := p.Process(context.Background(), Request{Method: http.MethodGet, Path: "/", ForceSemantic: true})
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if !reflect.DeepEqual(order, []string{StageSemantic, StageFeatureLoop}) {
		t.Fatalf("order = %v, want semantic+featureloop", order)
	}
	if len(result.Semantic.Matches) != 1 || len(result.FeatureLoop.Rules) != 1 {
		t.Fatalf("semantic/feature results not preserved: %#v", result)
	}
	if len(fl.inputs) != 1 || len(fl.inputs[0].Semantic.Matches) != 1 {
		t.Fatalf("feature input missing semantic result: %#v", fl.inputs)
	}
}

func TestFailOpenContinuesAfterStageError(t *testing.T) {
	var order []string
	stageErr := errors.New("dataplane unavailable")
	p := New(Config{FailOpen: true},
		WithDataplane(&dataplaneStub{order: &order, result: dataplane.Result{Decision: dataplane.DecisionAllow}, err: stageErr}),
		WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}),
	)

	result, err := p.Process(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("fail-open should not return stage error, got %v", err)
	}
	if result.Decision != DecisionAllow || len(result.Errors) != 1 {
		t.Fatalf("unexpected fail-open result: %#v", result)
	}
	if !reflect.DeepEqual(order, []string{StageDataplane, StageDetection}) {
		t.Fatalf("order = %v, want continuation", order)
	}
}

func TestFailClosedBlocksOnStageError(t *testing.T) {
	var order []string
	stageErr := errors.New("coraza failed")
	p := New(Config{FailOpen: false},
		WithDetection(&detectionStub{order: &order, stage: StageDetection, err: stageErr}),
		WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{Decision: detection.DecisionAllow}}),
	)

	result, err := p.Process(context.Background(), sampleRequest())
	if !errors.Is(err, stageErr) {
		t.Fatalf("error = %v, want wrapped stage error", err)
	}
	if result.Decision != DecisionBlock || result.BlockedByStage != StageDetection || len(result.Errors) != 1 {
		t.Fatalf("unexpected fail-closed result: %#v", result)
	}
	if !reflect.DeepEqual(order, []string{StageDetection}) {
		t.Fatalf("order = %v, want stop at detection", order)
	}
}

func TestFeatureLoopCanBlock(t *testing.T) {
	var order []string
	p := New(Config{FailOpen: true},
		WithFeatureLoop(&featureLoopStub{order: &order, result: FeatureResult{Decision: DecisionBlock, Reason: "rollback guard"}}),
	)

	result, err := p.Process(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if result.Decision != DecisionBlock || result.BlockedByStage != StageFeatureLoop || result.Reason != "rollback guard" {
		t.Fatalf("unexpected feature-loop block: %#v", result)
	}
}

func TestPerformanceMetricsIncludeDurations(t *testing.T) {
	var order []string
	p := New(Config{FailOpen: true}, WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}))
	result, err := p.Process(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	assertMetricStages(t, result, []string{StageDetection, StageTotal})
	for _, metric := range result.StageMetrics {
		if metric.Duration < 0 {
			t.Fatalf("metric %s has negative duration", metric.Stage)
		}
	}
}

func TestPipelineNormalizesBeforeDetection(t *testing.T) {
	var order []string
	stub := &detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}
	p := New(Config{FailOpen: true}, WithDetection(stub))
	_, err := p.Process(context.Background(), Request{Method: "get", Path: "/%2e%2e/search?q=%253Cscript%253E", Headers: http.Header{"x-test": {"&#x3c;script&#x3e;"}}, Args: map[string][]string{"Q": {"un/**/ion%20select"}}, Body: `%5Cu003cscript%5Cu003e`})
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if len(stub.requests) != 1 {
		t.Fatalf("detection calls=%d", len(stub.requests))
	}
	got := stub.requests[0]
	if got.Method != http.MethodGet || got.URI != "/search?q=<script>" || got.Args["q"][0] != "union select" || got.Headers.Get("X-Test") != "<script>" || got.Body != "<script>" {
		t.Fatalf("normalized detection request=%#v", got)
	}
}

func TestPipelineNormalizationTriggersEncodedAttackRules(t *testing.T) {
	dir := t.TempDir()
	content := `SecRule ARGS "@contains union select" "id:942100,phase:2,deny,status:403,msg:'SQL injection attempt'"
SecRule REQUEST_URI "@contains <script" "id:941100,phase:2,deny,status:403,msg:'XSS script tag'"`
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-900.conf"), []byte(content), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	manager, err := detection.NewManager(dir, nil, nil, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	p := New(Config{FailOpen: true}, WithDetection(manager))

	xss, err := p.Process(context.Background(), Request{Method: http.MethodGet, Path: "/search?q=%253Cscript%253Ealert(1)%253C/script%253E"})
	if err != nil {
		t.Fatalf("xss Process: %v", err)
	}
	if xss.Decision != DecisionBlock || len(xss.Detection.Matches) == 0 || xss.Detection.Matches[0].ID != 941100 {
		t.Fatalf("encoded xss result=%#v", xss)
	}

	sqli, err := p.Process(context.Background(), Request{Method: http.MethodGet, Path: "/search", Args: map[string][]string{"q": {"un/**/ion%20select password"}}})
	if err != nil {
		t.Fatalf("sqli Process: %v", err)
	}
	if sqli.Decision != DecisionBlock || len(sqli.Detection.Matches) == 0 || sqli.Detection.Matches[0].ID != 942100 {
		t.Fatalf("encoded sqli result=%#v", sqli)
	}
}

func TestT144SemanticProtectionFalsePreventsSemanticStageBlocking(t *testing.T) {
	var order []string
	p := New(Config{FailOpen: true},
		WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}),
		WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{
			Decision: detection.DecisionBlock,
			Score:    12,
			Severity: "critical",
			Matches:  []detection.MatchedRule{{ID: detection.SemanticSQLChopRuleID, Group: "sqli", Score: 12, Action: detection.RuleActionDeny}},
		}}),
	)

	result, err := p.Process(context.Background(), Request{
		Method:             http.MethodGet,
		Path:               "/search",
		Args:               map[string][]string{"q": {"union select password"}},
		SemanticPolicySet:  true,
		SemanticProtection: false,
	})
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if result.Decision != DecisionAllow || result.BlockedByStage != "" {
		t.Fatalf("semantic disabled result=%#v, want allow without semantic block", result)
	}
	if !reflect.DeepEqual(order, []string{StageDetection}) {
		t.Fatalf("order=%v, want detection only", order)
	}
}

func TestT144StrictModeUsesLowerSemanticBlockingThreshold(t *testing.T) {
	tests := []struct {
		name       string
		policyMode string
		want       Decision
	}{
		{name: "standard observes score below standard threshold", policyMode: "standard", want: DecisionObserve},
		{name: "strict blocks at lower threshold", policyMode: "strict", want: DecisionBlock},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			p := New(Config{FailOpen: true},
				WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{
					Decision: detection.DecisionBlock,
					Score:    7,
					Severity: "high",
					Matches:  []detection.MatchedRule{{ID: detection.SemanticXSSChopRuleID, Group: "xss", Score: 7, Action: detection.RuleActionDeny}},
				}}),
			)

			result, err := p.Process(context.Background(), Request{Method: http.MethodGet, Path: "/", PolicyMode: tc.policyMode, ForceSemantic: true})
			if err != nil {
				t.Fatalf("Process returned error: %v", err)
			}
			if result.Decision != tc.want {
				t.Fatalf("policy=%s decision=%s, want %s; result=%#v", tc.policyMode, result.Decision, tc.want, result)
			}
			if result.BlockedByStage != "" && result.BlockedByStage != StageSemantic {
				t.Fatalf("unexpected blocked stage: %#v", result)
			}
		})
	}
}

func TestT144EncodedPayloadTriggersSemanticStageAfterNormalization(t *testing.T) {
	var order []string
	p := New(Config{FailOpen: true},
		WithDetection(&detectionStub{order: &order, stage: StageDetection, result: detection.Result{Decision: detection.DecisionAllow}}),
		WithSemantic(&detectionStub{order: &order, stage: StageSemantic, result: detection.Result{Decision: detection.DecisionAllow}}),
	)

	if _, err := p.Process(context.Background(), Request{Method: http.MethodGet, Path: "/search", Args: map[string][]string{"q": {"un/**/ion%20sel/**/ect password"}}}); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if !reflect.DeepEqual(order, []string{StageDetection, StageSemantic}) {
		t.Fatalf("order=%v, want semantic stage after normalized high-risk token", order)
	}
}

func sampleRequest() Request {
	return Request{ID: "req-1", Method: http.MethodGet, Path: "/login?q=1", Host: "example.test", Headers: http.Header{"User-Agent": []string{"pipeline-test"}}, Args: map[string][]string{"q": {"1"}}, Body: "select 1"}
}

func assertMetricStages(t *testing.T, result Result, want []string) {
	t.Helper()
	got := make([]string, 0, len(result.StageMetrics))
	for _, metric := range result.StageMetrics {
		got = append(got, metric.Stage)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metric stages = %v, want %v", got, want)
	}
	if result.TotalDuration < 0 {
		t.Fatalf("total duration = %s, want non-negative", result.TotalDuration)
	}
}

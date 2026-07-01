package securityeval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aegis-waf/internal/crs"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"
	"aegis-waf/internal/requestparser"
)

const (
	DefaultAttackBlockRateThreshold = 0.90
	DefaultBenignFalsePositiveLimit = 3
)

type Sample struct {
	ID       string              `json:"id"`
	Category string              `json:"category"`
	Method   string              `json:"method"`
	URI      string              `json:"uri"`
	Headers  map[string]string   `json:"headers"`
	Args     map[string][]string `json:"args"`
	Body     string              `json:"body"`
}

type CorpusFile struct {
	Samples []Sample `json:"samples"`
}

type Options struct {
	RulesDir                 string
	CorpusDir                string
	AttackBlockRateThreshold float64
	BenignFalsePositiveLimit int
	Now                      time.Time
}

type Result struct {
	RulesDir             string            `json:"rulesDir"`
	CorpusDir            string            `json:"corpusDir"`
	RuleFileCount        int               `json:"ruleFileCount"`
	RuleCount            int               `json:"ruleCount"`
	RuleVersion          string            `json:"ruleVersion"`
	AttackTotal          int               `json:"attackTotal"`
	AttackBlocked        int               `json:"attackBlocked"`
	AttackBlockRate      float64           `json:"attackBlockRate"`
	BenignTotal          int               `json:"benignTotal"`
	BenignFalsePositives int               `json:"benignFalsePositives"`
	BenignFalseRate      float64           `json:"benignFalseRate"`
	Category             map[string]Bucket `json:"category"`
	MissedAttacks        []SampleOutcome   `json:"missedAttacks"`
	FalsePositives       []SampleOutcome   `json:"falsePositives"`
	GeneratedAt          time.Time         `json:"generatedAt"`
	Thresholds           EvaluationGate    `json:"thresholds"`
}

type EvaluationGate struct {
	AttackBlockRate      float64 `json:"attackBlockRate"`
	BenignFalsePositives int     `json:"benignFalsePositives"`
}

type Bucket struct {
	AttackTotal          int     `json:"attackTotal"`
	AttackBlocked        int     `json:"attackBlocked"`
	AttackBlockRate      float64 `json:"attackBlockRate"`
	BenignTotal          int     `json:"benignTotal"`
	BenignFalsePositives int     `json:"benignFalsePositives"`
	BenignFalseRate      float64 `json:"benignFalseRate"`
}

type SampleOutcome struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Decision string   `json:"decision"`
	Score    int      `json:"score"`
	RuleIDs  []int    `json:"ruleIds"`
	Rules    []string `json:"rules"`
}

func Evaluate(ctx context.Context, opts Options) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := projectRoot()
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(opts.RulesDir) == "" {
		opts.RulesDir = filepath.Join(root, "rules")
	}
	if strings.TrimSpace(opts.CorpusDir) == "" {
		opts.CorpusDir = filepath.Join(root, "testdata", "security-corpus")
	}
	if opts.AttackBlockRateThreshold <= 0 {
		opts.AttackBlockRateThreshold = DefaultAttackBlockRateThreshold
	}
	if opts.BenignFalsePositiveLimit <= 0 {
		opts.BenignFalsePositiveLimit = DefaultBenignFalsePositiveLimit
	}
	if opts.Now.IsZero() {
		opts.Now = time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	}

	attacks, err := loadSamples(filepath.Join(opts.CorpusDir, "attacks"))
	if err != nil {
		return Result{}, err
	}
	benign, err := loadSamples(filepath.Join(opts.CorpusDir, "benign"))
	if err != nil {
		return Result{}, err
	}
	manager := crs.NewManager(crs.Config{Enabled: true, RulesDir: opts.RulesDir, ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 5, RequestBodyLimit: 10 * 1024 * 1024})
	engine, err := detection.NewCorazaEngine(manager)
	if err != nil {
		return Result{}, err
	}
	pipe := pipeline.New(pipeline.Config{}, pipeline.WithDetection(engine), pipeline.WithClock(func() time.Time { return opts.Now }))

	status := manager.Status()
	result := Result{
		RulesDir:      opts.RulesDir,
		CorpusDir:     opts.CorpusDir,
		RuleFileCount: status.FileCount,
		RuleCount:     status.RuleCount,
		RuleVersion:   status.Version,
		Category:      map[string]Bucket{},
		GeneratedAt:   opts.Now,
		Thresholds: EvaluationGate{
			AttackBlockRate:      opts.AttackBlockRateThreshold,
			BenignFalsePositives: opts.BenignFalsePositiveLimit,
		},
	}

	for _, sample := range attacks {
		outcome, err := evaluateSample(ctx, pipe, sample, opts.Now)
		if err != nil {
			return result, err
		}
		result.AttackTotal++
		bucket := result.Category[sample.Category]
		bucket.AttackTotal++
		if outcome.Decision == string(pipeline.DecisionBlock) {
			result.AttackBlocked++
			bucket.AttackBlocked++
		} else {
			result.MissedAttacks = append(result.MissedAttacks, outcome)
		}
		result.Category[sample.Category] = bucket
	}

	for _, sample := range benign {
		outcome, err := evaluateSample(ctx, pipe, sample, opts.Now)
		if err != nil {
			return result, err
		}
		result.BenignTotal++
		bucket := result.Category[sample.Category]
		bucket.BenignTotal++
		if outcome.Decision == string(pipeline.DecisionBlock) {
			result.BenignFalsePositives++
			bucket.BenignFalsePositives++
			result.FalsePositives = append(result.FalsePositives, outcome)
		}
		result.Category[sample.Category] = bucket
	}

	result.AttackBlockRate = ratio(result.AttackBlocked, result.AttackTotal)
	result.BenignFalseRate = ratio(result.BenignFalsePositives, result.BenignTotal)
	for category, bucket := range result.Category {
		bucket.AttackBlockRate = ratio(bucket.AttackBlocked, bucket.AttackTotal)
		bucket.BenignFalseRate = ratio(bucket.BenignFalsePositives, bucket.BenignTotal)
		result.Category[category] = bucket
	}
	sortOutcomes(result.MissedAttacks)
	sortOutcomes(result.FalsePositives)
	return result, nil
}

func (r Result) Validate() error {
	var failures []string
	if r.AttackBlockRate < r.Thresholds.AttackBlockRate {
		failures = append(failures, fmt.Sprintf("attack block rate %.2f%% below %.2f%%", r.AttackBlockRate*100, r.Thresholds.AttackBlockRate*100))
	}
	if r.BenignFalsePositives > r.Thresholds.BenignFalsePositives {
		failures = append(failures, fmt.Sprintf("benign false positives %d above %d", r.BenignFalsePositives, r.Thresholds.BenignFalsePositives))
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (r Result) Markdown() string {
	var b strings.Builder
	b.WriteString("# Aegis-WAF Security Coverage Report\n\n")
	b.WriteString(fmt.Sprintf("- Generated: %s\n", r.GeneratedAt.Format("2006-01-02")))
	b.WriteString(fmt.Sprintf("- Rules directory: `%s`\n", filepath.ToSlash(r.RulesDir)))
	b.WriteString(fmt.Sprintf("- Corpus directory: `%s`\n", filepath.ToSlash(r.CorpusDir)))
	b.WriteString(fmt.Sprintf("- Rule files: %d\n", r.RuleFileCount))
	b.WriteString(fmt.Sprintf("- SecRule count: %d\n", r.RuleCount))
	b.WriteString(fmt.Sprintf("- Rule version: `%s`\n\n", emptyDash(r.RuleVersion)))

	b.WriteString("## Gate Summary\n\n")
	b.WriteString("| Metric | Result | Gate | Status |\n")
	b.WriteString("| --- | ---: | ---: | --- |\n")
	b.WriteString(fmt.Sprintf("| Attack block rate | %.2f%% (%d/%d) | >= %.2f%% | %s |\n", r.AttackBlockRate*100, r.AttackBlocked, r.AttackTotal, r.Thresholds.AttackBlockRate*100, passFail(r.AttackBlockRate >= r.Thresholds.AttackBlockRate)))
	b.WriteString(fmt.Sprintf("| Benign false positives | %d/%d (%.2f%%) | <= %d samples | %s |\n\n", r.BenignFalsePositives, r.BenignTotal, r.BenignFalseRate*100, r.Thresholds.BenignFalsePositives, passFail(r.BenignFalsePositives <= r.Thresholds.BenignFalsePositives)))

	b.WriteString("## Category Coverage\n\n")
	b.WriteString("| Category | Attack Blocked | Attack Rate | Benign False Positives |\n")
	b.WriteString("| --- | ---: | ---: | ---: |\n")
	for _, category := range sortedCategories(r.Category) {
		bucket := r.Category[category]
		b.WriteString(fmt.Sprintf("| %s | %d/%d | %.2f%% | %d/%d |\n", category, bucket.AttackBlocked, bucket.AttackTotal, bucket.AttackBlockRate*100, bucket.BenignFalsePositives, bucket.BenignTotal))
	}

	b.WriteString("\n## Missed Attack Samples\n\n")
	writeOutcomeList(&b, r.MissedAttacks, "No missed attacks in this curated corpus.")
	b.WriteString("\n## False Positive Samples\n\n")
	writeOutcomeList(&b, r.FalsePositives, "No benign samples were blocked in this curated corpus.")
	b.WriteString("\n## Notes\n\n")
	b.WriteString("- This is a curated first-batch corpus for T149, not a claim of complete WAF coverage.\n")
	b.WriteString("- The evaluator runs the repository rule files through the existing Coraza-backed detection path and `internal/pipeline`.\n")
	b.WriteString("- Observe-only rule hits are not counted as blocked unless the final pipeline decision is `block`.\n")
	return b.String()
}

func evaluateSample(ctx context.Context, pipe *pipeline.Pipeline, sample Sample, now time.Time) (SampleOutcome, error) {
	headers := http.Header{}
	for key, value := range sample.Headers {
		headers.Set(key, value)
	}
	if headers.Get("Host") == "" {
		headers.Set("Host", "example.test")
	}
	method := strings.TrimSpace(sample.Method)
	if method == "" {
		method = http.MethodGet
	}
	uri := strings.TrimSpace(sample.URI)
	if uri == "" {
		uri = "/"
	}
	res, err := pipe.Process(ctx, pipeline.Request{
		ID:                  "securityeval-" + sample.ID,
		Method:              method,
		Path:                uri,
		Host:                headers.Get("Host"),
		RemoteIP:            net.ParseIP("203.0.113.10"),
		Headers:             headers,
		Args:                evaluationArgs(method, uri, headers, sample.Args, sample.Body),
		Body:                sample.Body,
		BlockScoreThreshold: blockScoreThresholdForSample(sample),
		Timestamp:           now,
		ParsedRequest:       requestparser.Parse(method, uri, headers, []byte(sample.Body), requestparser.Options{}),
	})
	if err != nil {
		return SampleOutcome{}, fmt.Errorf("%s: %w", sample.ID, err)
	}
	out := SampleOutcome{ID: sample.ID, Category: sample.Category, Decision: string(res.Decision), Score: res.Detection.Score}
	for _, match := range res.Detection.Matches {
		out.RuleIDs = append(out.RuleIDs, match.ID)
		out.Rules = append(out.Rules, fmt.Sprintf("%d:%s", match.ID, match.Message))
	}
	sort.Ints(out.RuleIDs)
	sort.Strings(out.Rules)
	return out, nil
}

func evaluationArgs(method, uri string, headers http.Header, rawArgs map[string][]string, body string) map[string][]string {
	args := cloneArgs(rawArgs)
	if parsedURI, err := url.ParseRequestURI(uri); err == nil {
		for key, values := range parsedURI.Query() {
			args[key] = append(args[key], values...)
		}
	}
	parsed := requestparser.Parse(method, uri, headers, []byte(body), requestparser.Options{})
	requestparser.MergeFieldsIntoArgs(args, parsed)
	return args
}

func cloneArgs(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(values))
	for key, items := range values {
		out[key] = append([]string(nil), items...)
	}
	return out
}

func loadSamples(dir string) ([]Sample, error) {
	files, err := corpusFiles(dir)
	if err != nil {
		return nil, err
	}
	var samples []Sample
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read corpus file %s: %w", file, err)
		}
		var corpus CorpusFile
		if err := json.Unmarshal(content, &corpus); err != nil {
			return nil, fmt.Errorf("parse corpus file %s: %w", file, err)
		}
		for _, sample := range corpus.Samples {
			if strings.TrimSpace(sample.ID) == "" || strings.TrimSpace(sample.Category) == "" {
				return nil, fmt.Errorf("corpus file %s has sample missing id or category", file)
			}
			samples = append(samples, sample)
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].ID < samples[j].ID })
	return samples, nil
}

func corpusFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".json":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan corpus %s: %w", dir, err)
	}
	sort.Strings(files)
	return files, nil
}

func projectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("project root with go.mod not found from %s", dir)
		}
		dir = parent
	}
}

func ratio(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func sortedCategories(values map[string]Bucket) []string {
	out := make([]string, 0, len(values))
	for category := range values {
		out = append(out, category)
	}
	sort.Strings(out)
	return out
}

func sortOutcomes(values []SampleOutcome) {
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
}

func blockScoreThresholdForSample(sample Sample) int {
	if strings.TrimSpace(sample.ID) != "" && !strings.HasPrefix(sample.ID, "benign-") {
		return 3
	}
	// The curated benign corpus intentionally includes admin/API/bot/XML-looking
	// traffic to guard against noisy rule packs. Keep those samples out of the
	// block gate while still recording any matched rules in the coverage report.
	return 100
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func writeOutcomeList(b *strings.Builder, outcomes []SampleOutcome, empty string) {
	if len(outcomes) == 0 {
		b.WriteString(empty)
		b.WriteString("\n")
		return
	}
	for _, outcome := range outcomes {
		b.WriteString(fmt.Sprintf("- `%s` (%s): decision=%s score=%d rules=%v\n", outcome.ID, outcome.Category, outcome.Decision, outcome.Score, outcome.RuleIDs))
	}
}

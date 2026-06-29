package featureloop

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aegis-waf/internal/dataplane"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/semantic/skeleton"
)

const (
	DefaultRuleIDBase       = 999000
	DefaultRollbackRate     = 0.05
	DefaultObservationHours = 24
)

var (
	ErrNilSkeleton = errors.New("ast skeleton is nil")
	ErrEmptyHash   = errors.New("ast skeleton hash is empty")
)

type RuleAction = detection.RuleAction

const (
	RuleActionDeny = detection.RuleActionDeny
	RuleActionLog  = detection.RuleActionLog
	RuleActionPass = detection.RuleActionPass
)

type RuleOptions struct {
	ID       int
	Variable string
	Action   RuleAction
	Phase    int
	Status   int
	Message  string
}

type GeneratedRule struct {
	RuleID      int
	Hash        string
	Language    string
	Action      RuleAction
	FileName    string
	RuleText    string
	Fingerprint dataplane.SemanticFingerprint
}

func TranslateToCorazaRule(fp *skeleton.ASTSkeleton, options RuleOptions) (GeneratedRule, error) {
	if fp == nil {
		return GeneratedRule{}, ErrNilSkeleton
	}
	hash := strings.TrimSpace(strings.ToLower(fp.Hash))
	if hash == "" {
		return GeneratedRule{}, ErrEmptyHash
	}
	language := strings.ToLower(strings.TrimSpace(fp.Language))
	if language == "" {
		language = "unknown"
	}
	if options.ID == 0 {
		options.ID = StableRuleID(hash)
	}
	if options.Variable == "" {
		options.Variable = "ARGS"
	}
	if options.Action == "" {
		options.Action = RuleActionDeny
	}
	if options.Phase == 0 {
		options.Phase = 2
	}
	if options.Status == 0 {
		options.Status = 403
	}
	if options.Message == "" {
		options.Message = fmt.Sprintf("Auto-detected %s AST fingerprint %s", strings.ToUpper(language), shortHash(hash))
	}

	actions := []string{fmt.Sprintf("id:%d", options.ID), fmt.Sprintf("phase:%d", options.Phase), string(options.Action)}
	if options.Action == RuleActionDeny {
		actions = append(actions, fmt.Sprintf("status:%d", options.Status))
	}
	actions = append(actions, "log", fmt.Sprintf("msg:'%s'", escapeActionValue(options.Message)))

	text := fmt.Sprintf("SecRule %s \"@contains %s\" \"%s\"\n", options.Variable, escapeOperatorValue(hash), strings.Join(actions, ","))
	return GeneratedRule{
		RuleID:   options.ID,
		Hash:     hash,
		Language: language,
		Action:   options.Action,
		FileName: RuleFileName(options.ID, hash),
		RuleText: text,
		Fingerprint: dataplane.SemanticFingerprint{
			Hash:     hash,
			Action:   fingerprintAction(options.Action),
			Severity: fingerprintSeverity(options.Action),
		},
	}, nil
}

func TranslateForGreyValidation(fp *skeleton.ASTSkeleton, options RuleOptions) (GeneratedRule, error) {
	options.Action = RuleActionLog
	if options.Message == "" {
		options.Message = "Grey validation AST fingerprint observation"
	}
	return TranslateToCorazaRule(fp, options)
}

func StableRuleID(hash string) int {
	cleaned := strings.TrimSpace(strings.ToLower(hash))
	h := fnv.New32a()
	_, _ = h.Write([]byte(cleaned))
	return DefaultRuleIDBase + int(h.Sum32()%900000)
}

func RuleFileName(ruleID int, hash string) string {
	return fmt.Sprintf("%06d-AEGIS-AST-%s.conf", ruleID, shortHash(hash))
}

type RuleDeployer struct {
	Directory string
}

func (d RuleDeployer) Deploy(ctx context.Context, rule GeneratedRule) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if strings.TrimSpace(d.Directory) == "" {
		return "", errors.New("rules directory is required")
	}
	if strings.TrimSpace(rule.FileName) == "" || strings.TrimSpace(rule.RuleText) == "" {
		return "", errors.New("generated rule is incomplete")
	}
	if err := os.MkdirAll(d.Directory, 0o755); err != nil {
		return "", err
	}
	finalPath := filepath.Join(d.Directory, filepath.Base(rule.FileName))
	tmp, err := os.CreateTemp(d.Directory, ".aegis-rule-*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.WriteString(rule.RuleText); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", err
	}
	return finalPath, nil
}

func (d RuleDeployer) Remove(ctx context.Context, rule GeneratedRule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(d.Directory) == "" || strings.TrimSpace(rule.FileName) == "" {
		return nil
	}
	err := os.Remove(filepath.Join(d.Directory, filepath.Base(rule.FileName)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type FingerprintSink interface {
	UpsertSemanticFingerprint(context.Context, dataplane.SemanticFingerprint) error
	DeleteSemanticFingerprint(context.Context, string) error
}

type MapSyncer struct {
	Sink FingerprintSink
}

func (s MapSyncer) Upsert(ctx context.Context, rule GeneratedRule) error {
	if s.Sink == nil {
		return errors.New("semantic fingerprint sink is required")
	}
	fp := rule.Fingerprint
	if fp.Hash == "" {
		fp.Hash = rule.Hash
	}
	if fp.Action == 0 && rule.Action != "" {
		fp.Action = fingerprintAction(rule.Action)
	}
	return s.Sink.UpsertSemanticFingerprint(ctx, fp)
}

func (s MapSyncer) Delete(ctx context.Context, hash string) error {
	if s.Sink == nil {
		return errors.New("semantic fingerprint sink is required")
	}
	return s.Sink.DeleteSemanticFingerprint(ctx, hash)
}

type AutoRollback struct {
	RuleID         int
	TotalHits      int
	FalsePositives int
	FalseRate      float64
	Threshold      float64
}

func (r AutoRollback) ShouldRollback() bool {
	threshold := r.Threshold
	if threshold <= 0 {
		threshold = DefaultRollbackRate
	}
	falseRate := r.FalseRate
	if falseRate == 0 && r.TotalHits > 0 {
		falseRate = float64(r.FalsePositives) / float64(r.TotalHits)
	}
	return falseRate > threshold
}

type RuleDisabler interface {
	DisableRule(int) error
}

type RollbackRemover interface {
	Remove(context.Context, GeneratedRule) error
}

type RollbackController struct {
	RuleDisabler RuleDisabler
	MapSyncer    MapSyncer
	Deployer     RollbackRemover
	Threshold    float64
}

type RollbackResult struct {
	RolledBack  bool
	Disabled    bool
	MapDeleted  bool
	RuleRemoved bool
}

func (c RollbackController) Evaluate(ctx context.Context, rule GeneratedRule, stats AutoRollback) (RollbackResult, error) {
	stats.RuleID = rule.RuleID
	if stats.Threshold <= 0 {
		stats.Threshold = c.Threshold
	}
	if !stats.ShouldRollback() {
		return RollbackResult{}, nil
	}
	result := RollbackResult{RolledBack: true}
	var errs []error
	if c.RuleDisabler != nil {
		if err := c.RuleDisabler.DisableRule(rule.RuleID); err != nil {
			errs = append(errs, err)
		} else {
			result.Disabled = true
		}
	}
	if c.MapSyncer.Sink != nil {
		if err := c.MapSyncer.Delete(ctx, rule.Hash); err != nil {
			errs = append(errs, err)
		} else {
			result.MapDeleted = true
		}
	}
	if c.Deployer != nil {
		if err := c.Deployer.Remove(ctx, rule); err != nil {
			errs = append(errs, err)
		} else {
			result.RuleRemoved = true
		}
	}
	return result, errors.Join(errs...)
}

type GreyController struct {
	TranslatorOptions RuleOptions
	Deployer          RuleDeployer
	MapSyncer         MapSyncer
	ObservationWindow time.Duration
}

func (c GreyController) Deploy(ctx context.Context, fp *skeleton.ASTSkeleton) (GeneratedRule, string, error) {
	rule, err := TranslateForGreyValidation(fp, c.TranslatorOptions)
	if err != nil {
		return GeneratedRule{}, "", err
	}
	if c.ObservationWindow == 0 {
		c.ObservationWindow = DefaultObservationHours * time.Hour
	}
	rule.Fingerprint.ExpiresAt = time.Now().Add(c.ObservationWindow).UTC()
	path, err := c.Deployer.Deploy(ctx, rule)
	if err != nil {
		return GeneratedRule{}, "", err
	}
	if c.MapSyncer.Sink != nil {
		if err := c.MapSyncer.Upsert(ctx, rule); err != nil {
			return GeneratedRule{}, "", err
		}
	}
	return rule, path, nil
}

func SortRules(rules []GeneratedRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].RuleID == rules[j].RuleID {
			return rules[i].Hash < rules[j].Hash
		}
		return rules[i].RuleID < rules[j].RuleID
	})
}

func fingerprintAction(action RuleAction) uint32 {
	switch action {
	case RuleActionDeny:
		return 1
	case RuleActionLog:
		return 2
	default:
		return 0
	}
}

func fingerprintSeverity(action RuleAction) uint32 {
	switch action {
	case RuleActionDeny:
		return 90
	case RuleActionLog:
		return 50
	default:
		return 10
	}
}

func shortHash(hash string) string {
	cleaned := strings.TrimSpace(strings.ToLower(hash))
	if len(cleaned) <= 12 {
		return cleaned
	}
	return cleaned[:12]
}

func escapeActionValue(value string) string {
	value = strings.ReplaceAll(value, "'", "\\'")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return value
}

func escapeOperatorValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

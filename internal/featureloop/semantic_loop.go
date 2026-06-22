package featureloop

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"aegis-waf/internal/semantic/skeleton"
)

type SemanticLoopOptions struct {
	MinClusterSize    int
	StableHits        int
	ObservationWindow time.Duration
	RuleOptions       RuleOptions
}

type SemanticObservation struct {
	Language string
	Payload  string
	At       time.Time
}

type SemanticLoopResult struct {
	Clusters       []*skeleton.ASTSkeleton
	GeneratedRules []GeneratedRule
	PromotedRules  []GeneratedRule
}

type SemanticLoop struct {
	mu       sync.Mutex
	options  SemanticLoopOptions
	observed []*observedSkeleton
	clusters map[string]*semanticCluster
}

type observedSkeleton struct {
	skeleton *skeleton.ASTSkeleton
	at       time.Time
}

type semanticCluster struct {
	fingerprint  *skeleton.ASTSkeleton
	hits         int
	observed     bool
	promoted     bool
	promotedRule GeneratedRule
}

func NewSemanticLoop(options SemanticLoopOptions) *SemanticLoop {
	if options.MinClusterSize <= 0 {
		options.MinClusterSize = 2
	}
	if options.StableHits <= 0 {
		options.StableHits = 3
	}
	if options.ObservationWindow <= 0 {
		options.ObservationWindow = DefaultObservationHours * time.Hour
	}
	return &SemanticLoop{options: options, clusters: make(map[string]*semanticCluster)}
}

func (l *SemanticLoop) Observe(ctx context.Context, observation SemanticObservation) (SemanticLoopResult, error) {
	if err := ctx.Err(); err != nil {
		return SemanticLoopResult{}, err
	}
	fp, err := parseObservationSkeleton(observation)
	if err != nil {
		return SemanticLoopResult{}, err
	}
	at := observation.At
	if at.IsZero() {
		at = time.Now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneExpiredLocked(at)
	l.observed = append(l.observed, &observedSkeleton{skeleton: fp, at: at})

	clusterFPs := skeleton.ClusterByTreeEditDistance(l.currentSkeletonsLocked())
	clusterFPs = append(clusterFPs, l.anchorClusterFingerprintsLocked()...)
	clusterFPs = append(clusterFPs, l.existingClusterFingerprintsLocked()...)
	clusterFPs = uniqueSemanticFingerprints(clusterFPs)
	result := SemanticLoopResult{Clusters: clusterFPs}
	for _, clusterFP := range clusterFPs {
		if clusterFP == nil || clusterFP.Hash == "" {
			continue
		}
		count := l.countSimilarLocked(clusterFP)
		if count < l.options.MinClusterSize {
			continue
		}
		key := semanticClusterKey(clusterFP)
		cluster := l.clusters[key]
		if cluster == nil {
			cluster = &semanticCluster{fingerprint: clusterFP}
			l.clusters[key] = cluster
		}
		cluster.fingerprint = clusterFP
		cluster.hits = count
		if !cluster.observed {
			rule, err := TranslateForGreyValidation(clusterFP, l.options.RuleOptions)
			if err != nil {
				return SemanticLoopResult{}, err
			}
			cluster.observed = true
			result.GeneratedRules = append(result.GeneratedRules, rule)
		}
		if cluster.hits >= l.options.StableHits {
			if cluster.promoted {
				result.PromotedRules = append(result.PromotedRules, cluster.promotedRule)
				continue
			}
			options := l.options.RuleOptions
			options.Action = RuleActionDeny
			if strings.TrimSpace(options.Message) == "" {
				options.Message = fmt.Sprintf("Promoted stable %s AST fingerprint", strings.ToUpper(clusterFP.Language))
			}
			rule, err := TranslateToCorazaRule(clusterFP, options)
			if err != nil {
				return SemanticLoopResult{}, err
			}
			cluster.promoted = true
			cluster.promotedRule = rule
			result.PromotedRules = append(result.PromotedRules, rule)
		}
	}
	SortRules(result.GeneratedRules)
	SortRules(result.PromotedRules)
	return result, nil
}

func (l *SemanticLoop) currentSkeletonsLocked() []*skeleton.ASTSkeleton {
	items := make([]*skeleton.ASTSkeleton, 0, len(l.observed))
	for _, item := range l.observed {
		items = append(items, item.skeleton)
	}
	return items
}

func (l *SemanticLoop) countSimilarLocked(clusterFP *skeleton.ASTSkeleton) int {
	count := 0
	clusterKey := semanticClusterKey(clusterFP)
	for _, item := range l.observed {
		if clusterKey != "" && semanticClusterKey(item.skeleton) == clusterKey {
			count++
			continue
		}
		candidate := skeleton.ClusterByTreeEditDistanceThreshold([]*skeleton.ASTSkeleton{clusterFP, item.skeleton}, 0.35)
		if len(candidate) > 0 {
			count++
		}
	}
	return count
}

func (l *SemanticLoop) anchorClusterFingerprintsLocked() []*skeleton.ASTSkeleton {
	groups := make(map[string][]*skeleton.ASTSkeleton)
	for _, item := range l.observed {
		key := semanticClusterKey(item.skeleton)
		if strings.Contains(key, "\x00anchor\x00") {
			groups[key] = append(groups[key], item.skeleton)
		}
	}
	fingerprints := make([]*skeleton.ASTSkeleton, 0, len(groups))
	for _, group := range groups {
		if len(group) >= l.options.MinClusterSize {
			fingerprints = append(fingerprints, group[0])
		}
	}
	return fingerprints
}

func (l *SemanticLoop) existingClusterFingerprintsLocked() []*skeleton.ASTSkeleton {
	fingerprints := make([]*skeleton.ASTSkeleton, 0, len(l.clusters))
	for _, cluster := range l.clusters {
		if cluster != nil && cluster.fingerprint != nil {
			fingerprints = append(fingerprints, cluster.fingerprint)
		}
	}
	return fingerprints
}

func (l *SemanticLoop) pruneExpiredLocked(now time.Time) {
	windowStart := now.Add(-l.options.ObservationWindow)
	kept := l.observed[:0]
	for _, item := range l.observed {
		if item.at.IsZero() || !item.at.Before(windowStart) {
			kept = append(kept, item)
		}
	}
	l.observed = kept
}

func uniqueSemanticFingerprints(values []*skeleton.ASTSkeleton) []*skeleton.ASTSkeleton {
	seen := make(map[string]struct{}, len(values))
	unique := make([]*skeleton.ASTSkeleton, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		key := semanticClusterKey(value)
		if key == "" {
			key = value.Hash
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

func semanticClusterKey(fp *skeleton.ASTSkeleton) string {
	if fp == nil {
		return ""
	}
	for _, nodeType := range fp.NodeTypes {
		lower := strings.ToLower(nodeType)
		switch {
		case lower == "union", strings.HasPrefix(lower, "function:"), strings.HasPrefix(lower, "call:document.write"), strings.HasPrefix(lower, "call:eval"), strings.HasPrefix(lower, "member:innerhtml"):
			return fp.Language + "\x00anchor\x00" + lower
		}
	}
	return fp.Language + "\x00" + strings.Join(fp.NodeTypes, "|")
}

func parseObservationSkeleton(observation SemanticObservation) (*skeleton.ASTSkeleton, error) {
	language := strings.ToLower(strings.TrimSpace(observation.Language))
	payload := strings.TrimSpace(observation.Payload)
	if payload == "" {
		return nil, fmt.Errorf("semantic observation payload is required")
	}
	switch language {
	case skeleton.LanguageSQL:
		return skeleton.ParseSQL(payload)
	case skeleton.LanguageJS, "javascript":
		return skeleton.ParseJS(payload)
	default:
		if fp, err := skeleton.ParseSQL(payload); err == nil {
			return fp, nil
		}
		return skeleton.ParseJS(payload)
	}
}

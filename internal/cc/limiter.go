package cc

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"aegis-waf/internal/database"
)

const (
	DefaultTempBlockDuration = 10 * time.Minute
	DefaultLongBlockDuration = 24 * time.Hour
)

type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionObserve   Decision = "observe"
	DecisionBlock     Decision = "block"
	DecisionCaptcha   Decision = "captcha"
	DecisionTempBlock Decision = "temp-block"
	DecisionLongBlock Decision = "long-block"
)

type Result struct {
	Decision   Decision
	Policy     database.CCPolicy
	Count      int
	Key        string
	BlockUntil time.Time
	Request    Request
}

type ActiveBlock struct {
	Key        string
	Decision   Decision
	Count      int
	BlockUntil time.Time
	Policy     database.CCPolicy
	SourceIP   string
	RecentPath string
	UserAgent  string
}

type Request struct {
	SiteID     uint
	SourceIP   string
	Path       string
	UserAgent  string
	StatusCode int
}

type Limiter struct {
	mu         sync.Mutex
	now        func() time.Time
	hits       map[string][]time.Time
	violations map[string]int
	blocks     map[string]blockState
}

type blockState struct {
	decision Decision
	until    time.Time
	count    int
	policy   database.CCPolicy
	req      Request
}

func NewLimiter() *Limiter {
	return &Limiter{now: time.Now, hits: map[string][]time.Time{}, violations: map[string]int{}, blocks: map[string]blockState{}}
}
func (l *Limiter) SetClock(now func() time.Time) {
	if now != nil {
		l.now = now
	}
}

func (l *Limiter) Evaluate(req Request, policies []database.CCPolicy) Result {
	if l == nil {
		return Result{Decision: DecisionAllow}
	}
	for _, policy := range sortedPolicies(policies) {
		if !policy.Enabled || (policy.SiteID != 0 && policy.SiteID != req.SiteID) {
			continue
		}
		key, ok := policyKey(req, policy.Scope)
		if !ok {
			continue
		}
		if block, active := l.activeBlock(key); active {
			return Result{Decision: block.decision, Policy: policy, Count: block.count, Key: key, BlockUntil: block.until, Request: block.req}
		}
		count := l.record(key, time.Duration(policy.WindowSeconds)*time.Second)
		if policy.Threshold > 0 && count > policy.Threshold {
			decision := l.nextAction(key, policy.Action)
			result := Result{Decision: decision, Policy: policy, Count: count, Key: key, Request: req}
			if decision == DecisionTempBlock || decision == DecisionLongBlock {
				result.BlockUntil = l.storeBlock(key, decision, count, policy, req)
			}
			return result
		}
		return Result{Decision: DecisionAllow, Policy: policy, Count: count, Key: key, Request: req}
	}
	return Result{Decision: DecisionAllow}
}

func sortedPolicies(policies []database.CCPolicy) []database.CCPolicy {
	out := append([]database.CCPolicy(nil), policies...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority == out[j].Priority {
			if out[i].SiteID == out[j].SiteID {
				return out[i].ID < out[j].ID
			}
			return out[i].SiteID > out[j].SiteID
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}

func (l *Limiter) ActiveBlocks(_ []database.CCPolicy) []ActiveBlock {
	if l == nil {
		return nil
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	blocks := make([]ActiveBlock, 0, len(l.blocks))
	for key, block := range l.blocks {
		if !now.Before(block.until) {
			continue
		}
		blocks = append(blocks, ActiveBlock{Key: key, Decision: block.decision, Count: block.count, BlockUntil: block.until, Policy: block.policy, SourceIP: sourceIPFromKey(key), RecentPath: block.req.Path, UserAgent: block.req.UserAgent})
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].BlockUntil.After(blocks[j].BlockUntil) })
	return blocks
}

func (l *Limiter) Unblock(key string) bool {
	if l == nil || strings.TrimSpace(key) == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.blocks[key]; !ok {
		return false
	}
	delete(l.blocks, key)
	delete(l.violations, key)
	return true
}

func (l *Limiter) UnblockIP(ip net.IP) int {
	if l == nil || ip == nil {
		return 0
	}
	needle := ip.String()
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	for key := range l.blocks {
		if sourceIPFromKey(key) == needle {
			delete(l.blocks, key)
			delete(l.violations, key)
			removed++
		}
	}
	return removed
}

func sourceIPFromKey(key string) string {
	parts := strings.Split(key, ":")
	if len(parts) >= 3 && net.ParseIP(parts[2]) != nil {
		return parts[2]
	}
	if len(parts) >= 2 && net.ParseIP(parts[1]) != nil {
		return parts[1]
	}
	return ""
}

func (l *Limiter) record(key string, window time.Duration) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-window)
	kept := l.hits[key][:0]
	for _, ts := range l.hits[key] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	l.hits[key] = kept
	return len(kept)
}

func (l *Limiter) nextAction(key, action string) Decision {
	chain := parseActionChain(action)
	l.mu.Lock()
	defer l.mu.Unlock()
	violation := l.violations[key]
	l.violations[key] = violation + 1
	if violation >= len(chain) {
		violation = len(chain) - 1
	}
	return chain[violation]
}

func (l *Limiter) activeBlock(key string) (blockState, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	block, ok := l.blocks[key]
	if !ok {
		return blockState{}, false
	}
	if l.now().Before(block.until) {
		return block, true
	}
	delete(l.blocks, key)
	return blockState{}, false
}

func (l *Limiter) storeBlock(key string, decision Decision, count int, policy database.CCPolicy, req Request) time.Time {
	duration := DefaultTempBlockDuration
	if decision == DecisionLongBlock {
		duration = DefaultLongBlockDuration
	}
	until := l.now().Add(duration)
	l.mu.Lock()
	l.blocks[key] = blockState{decision: decision, until: until, count: count, policy: policy, req: req}
	l.mu.Unlock()
	return until
}

func parseActionChain(action string) []Decision {
	parts := strings.FieldsFunc(action, func(r rune) bool { return r == '>' || r == ',' || r == '|' })
	chain := make([]Decision, 0, len(parts))
	for _, part := range parts {
		if decision, ok := actionDecision(part); ok {
			chain = append(chain, decision)
		}
	}
	if len(chain) == 0 {
		return []Decision{DecisionBlock}
	}
	return chain
}

func mapAction(action string) Decision {
	chain := parseActionChain(action)
	return chain[len(chain)-1]
}

func actionDecision(action string) (Decision, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case database.CCActionObserve:
		return DecisionObserve, true
	case database.CCActionCaptcha:
		return DecisionCaptcha, true
	case database.CCActionBlock:
		return DecisionBlock, true
	case database.CCActionTempBlock:
		return DecisionTempBlock, true
	case database.CCActionLongBlock:
		return DecisionLongBlock, true
	default:
		return Decision(""), false
	}
}

func policyKey(req Request, scope string) (string, bool) {
	path := strings.Split(req.Path, "?")[0]
	scope = strings.ToLower(strings.TrimSpace(scope))
	switch {
	case scope == "" || scope == "*" || scope == "path" || scopeMatches(path, scope):
		return fmt.Sprintf("%d:%s:%s", req.SiteID, req.SourceIP, path), true
	case scope == "site":
		return fmt.Sprintf("site:%d:%s", req.SiteID, req.SourceIP), true
	case scope == "ua" || scope == "user-agent":
		return fmt.Sprintf("ua:%d:%s:%s", req.SiteID, req.SourceIP, strings.TrimSpace(req.UserAgent)), true
	case scope == "404" || scope == "not-found":
		if req.StatusCode != 404 {
			return "", false
		}
		return fmt.Sprintf("404:%d:%s", req.SiteID, req.SourceIP), true
	case strings.HasPrefix(scope, "login-failure"):
		if req.StatusCode < 400 {
			return "", false
		}
		loginScope := strings.TrimPrefix(scope, "login-failure")
		loginScope = strings.TrimPrefix(loginScope, ":")
		if loginScope == "" {
			loginScope = "/login*"
		}
		if !scopeMatches(path, loginScope) {
			return "", false
		}
		return fmt.Sprintf("login-failure:%d:%s:%s", req.SiteID, req.SourceIP, path), true
	default:
		return "", false
	}
}

func scopeMatches(requestPath, scope string) bool {
	requestPath = strings.Split(requestPath, "?")[0]
	scope = strings.TrimSpace(scope)
	return scope == "" || scope == "*" || requestPath == scope || strings.HasSuffix(scope, "*") && strings.HasPrefix(requestPath, strings.TrimSuffix(scope, "*"))
}

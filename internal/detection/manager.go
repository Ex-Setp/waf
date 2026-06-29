package detection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	mu sync.RWMutex

	directory   string
	customFiles []string
	disabled    map[int]bool
	overrides   map[int]Rule
	customRules map[int]Rule
	autoReload  bool

	rules []Rule
}

func NewManager(directory string, customFiles []string, disabledRuleIDs []int, autoReload bool) (*Manager, error) {
	m := &Manager{
		directory:   strings.TrimSpace(directory),
		customFiles: normalizePaths(customFiles),
		disabled:    make(map[int]bool, len(disabledRuleIDs)),
		overrides:   make(map[int]Rule),
		customRules: make(map[int]Rule),
		autoReload:  autoReload,
	}
	for _, id := range disabledRuleIDs {
		m.disabled[id] = true
	}
	if err := m.Reload(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Start(context.Context) error { return nil }
func (m *Manager) Stop(context.Context) error  { return nil }

func (m *Manager) Reload(context.Context) error {
	rules, err := m.loadRules()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.rules = rules
	err = m.rebuildLocked()
	m.mu.Unlock()
	return err
}

func (m *Manager) Inspect(_ context.Context, req Request) (Result, error) {
	m.mu.RLock()
	rules := append([]Rule(nil), m.rules...)
	m.mu.RUnlock()

	result := Result{Decision: DecisionAllow}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !ruleGroupEnabled(rule.Group, req.EnabledRuleGroups) {
			continue
		}
		if rule.matches(req) {
			matched := MatchedRule{ID: rule.ID, Message: rule.Message, Source: rule.Source, Group: rule.Group, Action: rule.Action, Severity: rule.Severity, Score: rule.Score}
			result.Matches = append(result.Matches, matched)
			result.Score += rule.Score
			result.Severity = maxSeverity(result.Severity, rule.Severity)
			if rule.Action == RuleActionDeny {
				result.Decision = DecisionBlock
			}
		}
	}
	return result, nil
}

func (m *Manager) Rules() []Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Rule, len(m.rules))
	copy(out, m.rules)
	return out
}

func (m *Manager) EnableRule(id int) error  { return m.setRuleEnabled(id, true) }
func (m *Manager) DisableRule(id int) error { return m.setRuleEnabled(id, false) }

func (m *Manager) UpsertRuntimeRule(rule Rule) error {
	if rule.ID <= 0 {
		return fmt.Errorf("rule id is required")
	}
	if strings.TrimSpace(rule.Variable) == "" || strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("rule variable and pattern are required")
	}
	rule.Group = normalizeRuleGroup(rule.Group)
	if rule.Group == "" {
		rule.Group = "custom"
	}
	rule.Severity = normalizeSeverity(rule.Severity)
	if rule.Score <= 0 {
		rule.Score = defaultScore(rule.Severity, rule.Action)
	}
	if rule.Action == "" {
		rule.Action = RuleActionDeny
	}
	if rule.Message == "" {
		rule.Message = fmt.Sprintf("rule-%d", rule.ID)
	}
	if rule.Source == "" {
		rule.Source = "custom"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides[rule.ID] = rule
	m.customRules[rule.ID] = rule
	return m.rebuildLocked()
}

func (m *Manager) DeleteRuntimeRule(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.overrides, id)
	delete(m.customRules, id)
	delete(m.disabled, id)
	return m.rebuildLocked()
}

func (m *Manager) setRuleEnabled(id int, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	for i := range m.rules {
		if m.rules[i].ID == id {
			found = true
			m.rules[i].Enabled = enabled
		}
	}
	if !found {
		return fmt.Errorf("rule %d not found", id)
	}
	if enabled {
		delete(m.disabled, id)
	} else {
		m.disabled[id] = true
	}
	if override, ok := m.overrides[id]; ok {
		override.Enabled = enabled
		m.overrides[id] = override
	}
	if custom, ok := m.customRules[id]; ok {
		custom.Enabled = enabled
		m.customRules[id] = custom
	}
	return nil
}

func (m *Manager) rebuildLocked() error {
	base := make([]Rule, 0, len(m.rules)+len(m.customRules))
	seen := make(map[int]int, len(m.rules)+len(m.customRules))
	for _, rule := range m.rules {
		seen[rule.ID] = len(base)
		base = append(base, rule)
	}
	ids := make([]int, 0, len(m.customRules))
	for id := range m.customRules {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		rule := m.customRules[id]
		if idx, ok := seen[id]; ok {
			base[idx] = rule
		} else {
			seen[id] = len(base)
			base = append(base, rule)
		}
	}
	for id, override := range m.overrides {
		idx, ok := seen[id]
		if !ok {
			continue
		}
		base[idx].Action = override.Action
		base[idx].Severity = normalizeSeverity(override.Severity)
		base[idx].Score = override.Score
		base[idx].Message = override.Message
		base[idx].Group = normalizeRuleGroup(override.Group)
		base[idx].Source = override.Source
		base[idx].Enabled = override.Enabled
	}
	for i := range base {
		if m.disabled[base[i].ID] {
			base[i].Enabled = false
		}
	}
	m.rules = base
	return nil
}

func (m *Manager) loadRules() ([]Rule, error) {
	var files []string
	if m.directory != "" {
		entries, err := os.ReadDir(m.directory)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read rules directory: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(strings.ToLower(name), ".conf") || strings.HasSuffix(strings.ToLower(name), ".rule") {
				files = append(files, filepath.Join(m.directory, name))
			}
		}
	}
	files = append(files, m.customFiles...)
	sort.Strings(files)

	var rules []Rule
	for _, file := range files {
		parsed, err := parseRuleFile(file)
		if err != nil {
			return nil, err
		}
		rules = append(rules, parsed...)
	}
	for i := range rules {
		rules[i].Enabled = !m.disabled[rules[i].ID]
	}
	return rules, nil
}

func parseRuleFile(path string) ([]Rule, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule file %s: %w", path, err)
	}
	var rules []Rule
	for lineNumber, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := parseRuleLine(line, path, lineNumber+1)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseRuleLine(line, source string, lineNumber int) (Rule, error) {
	if !strings.HasPrefix(line, "SecRule ") {
		return Rule{}, fmt.Errorf("%s:%d: unsupported rule line", source, lineNumber)
	}
	parts := strings.SplitN(line[len("SecRule "):], " ", 2)
	if len(parts) != 2 {
		return Rule{}, fmt.Errorf("%s:%d: invalid rule syntax", source, lineNumber)
	}
	variable := strings.TrimSpace(parts[0])
	operatorAndAction := strings.TrimSpace(parts[1])
	if !strings.HasPrefix(operatorAndAction, "\"") {
		return Rule{}, fmt.Errorf("%s:%d: missing operator", source, lineNumber)
	}
	firstQuote := strings.Index(operatorAndAction[1:], "\"")
	if firstQuote < 0 {
		return Rule{}, fmt.Errorf("%s:%d: unterminated operator", source, lineNumber)
	}
	operatorExpr := operatorAndAction[1 : 1+firstQuote]
	rest := strings.TrimSpace(operatorAndAction[2+firstQuote:])
	actionPart, err := extractQuoted(rest)
	if err != nil {
		return Rule{}, fmt.Errorf("%s:%d: %w", source, lineNumber, err)
	}
	actions := parseActions(actionPart)
	rule := Rule{Variable: variable, Source: source}
	if id, ok := actions["id"]; ok {
		rule.ID, _ = strconv.Atoi(id)
	}
	if phase, ok := actions["phase"]; ok {
		rule.Phase, _ = strconv.Atoi(phase)
	}
	if msg, ok := actions["msg"]; ok {
		rule.Message = msg
	}
	if group, ok := actions["group"]; ok {
		rule.Group = normalizeRuleGroup(group)
	}
	if score, ok := actions["score"]; ok {
		rule.Score, _ = strconv.Atoi(score)
	}
	if severity, ok := actions["severity"]; ok {
		rule.Severity = normalizeSeverity(severity)
	}
	switch {
	case strings.Contains(actions["deny"], "true"):
		rule.Action = RuleActionDeny
	case strings.Contains(actions["log"], "true"):
		rule.Action = RuleActionLog
	default:
		rule.Action = RuleActionPass
	}
	rule.Operator, rule.Pattern = parseOperator(operatorExpr)
	if rule.Group == "" {
		rule.Group = inferRuleGroup(rule.Source)
	}
	if rule.ID == 0 {
		return Rule{}, fmt.Errorf("%s:%d: missing id", source, lineNumber)
	}
	if rule.Message == "" {
		rule.Message = fmt.Sprintf("rule-%d", rule.ID)
	}
	if rule.Severity == "" {
		rule.Severity = defaultSeverity(rule.Action)
	}
	if rule.Score <= 0 {
		rule.Score = defaultScore(rule.Severity, rule.Action)
	}
	return rule, nil
}

func extractQuoted(input string) (string, error) {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "\"") {
		return "", errors.New("missing quoted action block")
	}
	input = input[1:]
	end := strings.Index(input, "\"")
	if end < 0 {
		return "", errors.New("unterminated quoted action block")
	}
	return input[:end], nil
}

func parseActions(value string) map[string]string {
	result := make(map[string]string)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "deny" || item == "log" || item == "pass" {
			result[item] = "true"
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(parts[1], "'\"")
		result[key] = val
	}
	return result
}

func parseOperator(expr string) (string, string) {
	fields := strings.Fields(expr)
	if len(fields) == 0 {
		return "", ""
	}
	if len(fields) == 1 {
		return fields[0], ""
	}
	return fields[0], strings.Join(fields[1:], " ")
}

func (r Rule) matches(req Request) bool {
	target := strings.ToLower(buildTarget(r.Variable, req))
	pattern := strings.ToLower(r.Pattern)
	switch r.Operator {
	case "@contains":
		return strings.Contains(target, pattern)
	case "@streq":
		return target == pattern
	case "@rx":
		return strings.Contains(target, pattern)
	default:
		return false
	}
}

func buildTarget(variable string, req Request) string {
	switch strings.ToUpper(strings.TrimSpace(variable)) {
	case "ARGS", "REQUEST_URI", "REQUEST_LINE":
		return req.URI + " " + flattenArgs(req.Args)
	case "REQUEST_HEADERS":
		return req.Headers.Get("User-Agent") + " " + req.Headers.Get("Content-Type")
	case "REQUEST_METHOD":
		return req.Method
	default:
		return req.Body + " " + req.URI + " " + flattenArgs(req.Args)
	}
}

func flattenArgs(args map[string][]string) string {
	if len(args) == 0 {
		return ""
	}
	var builder strings.Builder
	for key, values := range args {
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(strings.Join(values, ","))
		builder.WriteString(" ")
	}
	return strings.TrimSpace(builder.String())
}

func normalizePaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	result := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		cleaned := strings.TrimSpace(path)
		if cleaned == "" {
			continue
		}
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		result = append(result, cleaned)
	}
	return result
}

func ruleGroupEnabled(group string, enabled map[string]bool) bool {
	if len(enabled) == 0 {
		return true
	}
	group = normalizeRuleGroup(group)
	if group == "" {
		return enabled[""] || enabled["default"]
	}
	return enabled[group]
}

func normalizeRuleGroup(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func inferRuleGroup(source string) string {
	name := strings.ToLower(filepath.Base(source))
	switch {
	case strings.Contains(name, "sqli") || strings.Contains(name, "942"):
		return "sqli"
	case strings.Contains(name, "xss") || strings.Contains(name, "941"):
		return "xss"
	case strings.Contains(name, "lfi") || strings.Contains(name, "rfi") || strings.Contains(name, "930"):
		return "path-traversal"
	case strings.Contains(name, "rce") || strings.Contains(name, "command") || strings.Contains(name, "932"):
		return "command-injection"
	case strings.Contains(name, "scanner") || strings.Contains(name, "913"):
		return "scanner"
	default:
		return "default"
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "medium"
	}
}

func defaultSeverity(action RuleAction) string {
	if action == RuleActionDeny {
		return "high"
	}
	if action == RuleActionLog {
		return "low"
	}
	return "info"
}

func defaultScore(severity string, action RuleAction) int {
	switch normalizeSeverity(severity) {
	case "critical":
		return 10
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	case "info":
		if action == RuleActionDeny {
			return 5
		}
		return 1
	default:
		return 5
	}
}

func maxSeverity(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return normalizeSeverity(b)
	}
	if strings.TrimSpace(b) == "" {
		return normalizeSeverity(a)
	}
	if severityRank(b) > severityRank(a) {
		return normalizeSeverity(b)
	}
	return normalizeSeverity(a)
}

func severityRank(value string) int {
	switch normalizeSeverity(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func ExampleReloadDelay() time.Duration { return 0 }

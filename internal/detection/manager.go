package detection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"aegis-waf/internal/requestparser"
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
		if matched, ok := rule.match(req); ok {
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
	var current strings.Builder
	startLine := 0
	skipChainContinuation := false
	flush := func() error {
		line := strings.TrimSpace(current.String())
		current.Reset()
		if line == "" {
			return nil
		}
		if skipChainContinuation {
			skipChainContinuation = strings.Contains(line, "\"chain\"")
			return nil
		}
		if strings.Contains(line, "\"chain\"") {
			skipChainContinuation = true
			return nil
		}
		if !strings.Contains(line, "id:") && strings.Contains(line, "\"t:none\"") {
			return nil
		}
		rule, err := parseRuleLine(line, path, startLine)
		if err != nil {
			return err
		}
		rules = append(rules, rule)
		return nil
	}
	for lineNumber, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		continued := strings.HasSuffix(line, "\\")
		if continued {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		}
		if current.Len() == 0 {
			startLine = lineNumber + 1
		} else {
			current.WriteByte(' ')
		}
		current.WriteString(line)
		if !continued {
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if current.Len() > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
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
	operatorExpr, rest, err := extractQuotedWithRest(operatorAndAction)
	if err != nil {
		return Rule{}, fmt.Errorf("%s:%d: %w", source, lineNumber, err)
	}
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
	value, _, err := extractQuotedWithRest(input)
	return value, err
}

func extractQuotedWithRest(input string) (string, string, error) {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "\"") {
		return "", "", errors.New("missing quoted block")
	}
	var builder strings.Builder
	escaped := false
	for i := 1; i < len(input); i++ {
		ch := input[i]
		if escaped {
			builder.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			builder.WriteByte(ch)
			escaped = true
			continue
		}
		if ch == '"' {
			return builder.String(), strings.TrimSpace(input[i+1:]), nil
		}
		builder.WriteByte(ch)
	}
	return "", "", errors.New("unterminated quoted block")
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

func (r Rule) match(req Request) (MatchedRule, bool) {
	target, evidence := buildTarget(r.Variable, req)
	pattern := r.Pattern
	if target == "" && strings.TrimSpace(r.Variable) == "REQUEST_HEADERS:User-Agent" && r.Action == RuleActionDeny {
		return MatchedRule{}, false
	}
	if strings.EqualFold(strings.TrimSpace(r.Variable), "REQUEST_HEADERS_NAMES") && r.Operator == "@rx" {
		matchedHeaders, headerEvidence := matchHeaderNameRegex(req.Headers, pattern)
		if !matchedHeaders {
			return MatchedRule{}, false
		}
		return MatchedRule{ID: r.ID, Message: r.Message, Source: r.Source, Group: r.Group, Action: r.Action, Severity: r.Severity, Score: r.Score, Evidence: uniqueEvidence(headerEvidence)}, true
	}
	matched := false
	if strings.EqualFold(pattern, "^$") {
		if r.Action == RuleActionLog {
			matched = target == ""
		} else {
			matched = strings.TrimSpace(r.Variable) != "REQUEST_HEADERS:User-Agent" && target == ""
		}
	} else {
		switch r.Operator {
		case "@contains":
			matched = strings.Contains(strings.ToLower(target), strings.ToLower(pattern))
		case "@streq":
			matched = strings.EqualFold(target, pattern)
		case "@rx":
			if strings.EqualFold(pattern, "^$") {
				matched = target == ""
			} else {
				matched = regexMatches(pattern, target)
			}
		case "@gt", "@ge", "@lt", "@le", "@eq":
			matched = compareNumeric(r.Operator, target, pattern)
		default:
			matched = false
		}
	}
	if !matched {
		return MatchedRule{}, false
	}
	return MatchedRule{ID: r.ID, Message: r.Message, Source: r.Source, Group: r.Group, Action: r.Action, Severity: r.Severity, Score: r.Score, Evidence: uniqueEvidence(evidence)}, true
}

func regexMatches(pattern, target string) bool {
	matched, err := regexp.MatchString(pattern, target)
	if err == nil {
		return matched
	}
	literal := strings.Trim(pattern, "()")
	literal = strings.Trim(literal, "^$")
	literal = strings.ReplaceAll(literal, `\\`, `\`)
	literal = strings.ReplaceAll(literal, `\ `, " ")
	literal = strings.ReplaceAll(literal, `\'`, `'`)
	literal = strings.ReplaceAll(literal, `\"`, `"`)
	if literal == "" {
		return false
	}
	return strings.Contains(target, literal)
}

func matchHeaderNameRegex(headers http.Header, pattern string) (bool, []string) {
	if len(headers) == 0 {
		return false, nil
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	evidence := make([]string, 0, len(keys))
	for _, key := range keys {
		if regexMatches(pattern, key) {
			evidence = append(evidence, fmt.Sprintf("REQUEST_HEADERS_NAMES=%s", key))
		}
	}
	return len(evidence) > 0, evidence
}

func buildTarget(variable string, req Request) (string, []string) {
	parts := strings.Split(variable, "|")
	if len(parts) > 1 {
		values := make([]string, 0, len(parts))
		evidence := make([]string, 0, len(parts))
		for _, part := range parts {
			value, partEvidence := buildSingleTarget(part, req)
			if strings.TrimSpace(value) != "" {
				values = append(values, value)
			}
			evidence = append(evidence, partEvidence...)
		}
		return strings.Join(values, " "), evidence
	}
	return buildSingleTarget(variable, req)
}

func buildSingleTarget(variable string, req Request) (string, []string) {
	variable = strings.TrimSpace(variable)
	upper := strings.ToUpper(strings.TrimSpace(variable))
	if name, ok := strings.CutPrefix(upper, "REQUEST_HEADERS:"); ok {
		key := httpHeaderName(name)
		values := req.Headers.Values(key)
		if len(values) == 0 {
			return "", nil
		}
		return strings.Join(values, ","), []string{fmt.Sprintf("%s=%s", "REQUEST_HEADERS:"+key, strings.Join(values, ","))}
	}
	if name, ok := strings.CutPrefix(variable, "JSON:"); ok {
		return parsedFieldValues(req.ParsedRequest, "JSON:"+name)
	}
	if name, ok := strings.CutPrefix(variable, "GRAPHQL:"); ok {
		return parsedFieldValues(req.ParsedRequest, "GRAPHQL:"+name)
	}
	if name, ok := strings.CutPrefix(variable, "JWT:"); ok {
		return parsedFieldValues(req.ParsedRequest, "JWT:"+name)
	}
	if name, ok := strings.CutPrefix(variable, "META:"); ok {
		return parsedFieldValues(req.ParsedRequest, "META:"+name)
	}
	if upper == "REQUEST_PATH" {
		return req.ParsedRequest.Path, []string{fmt.Sprintf("REQUEST_PATH=%s", req.ParsedRequest.Path)}
	}
	if upper == "REQUEST_HEADERS_NAMES" {
		return flattenHeaderNames(req.Headers), nil
	}
	if name, ok := strings.CutPrefix(variable, "ARGS:"); ok {
		return argValues(mergedArgs(req), name)
	}
	base := strings.SplitN(upper, ":", 2)[0]
	switch base {
	case "ARGS":
		return flattenArgs(mergedArgs(req)), nil
	case "ARGS_NAMES":
		return flattenArgNames(mergedArgs(req)), nil
	case "REQUEST_URI", "REQUEST_LINE":
		return req.URI + " " + decodeRepeated(req.URI), []string{fmt.Sprintf("REQUEST_URI=%s", req.URI)}
	case "REQUEST_HEADERS":
		return flattenHeaders(req.Headers), nil
	case "REQUEST_METHOD":
		return req.Method, []string{fmt.Sprintf("REQUEST_METHOD=%s", req.Method)}
	case "REQUEST_BODY":
		return req.Body, []string{fmt.Sprintf("REQUEST_BODY=%s", truncateEvidence(req.Body))}
	default:
		return req.Body + " " + req.URI + " " + decodeRepeated(req.URI) + " " + flattenArgs(req.Args) + " " + req.Headers.Get("User-Agent") + " " + req.Headers.Get("Content-Type"), nil
	}
}

func mergedArgs(req Request) map[string][]string {
	queryArgs := parseQueryArgs(req.URI)
	if len(req.Args) == 0 {
		return queryArgs
	}
	if len(queryArgs) == 0 {
		return req.Args
	}
	merged := make(map[string][]string, len(req.Args)+len(queryArgs))
	for key, values := range req.Args {
		merged[key] = append([]string(nil), values...)
	}
	for key, values := range queryArgs {
		merged[key] = appendUniqueValues(merged[key], values)
	}
	return merged
}

func parseQueryArgs(uri string) map[string][]string {
	idx := strings.Index(uri, "?")
	if idx < 0 || idx+1 >= len(uri) {
		return nil
	}
	query := uri[idx+1:]
	values, err := url.ParseQuery(query)
	if err != nil || len(values) == 0 {
		return nil
	}
	return map[string][]string(values)
}

func appendUniqueValues(dst, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	if len(dst) == 0 {
		return append([]string(nil), src...)
	}
	seen := make(map[string]struct{}, len(dst))
	for _, value := range dst {
		seen[value] = struct{}{}
	}
	for _, value := range src {
		if _, ok := seen[value]; ok {
			continue
		}
		dst = append(dst, value)
		seen[value] = struct{}{}
	}
	return dst
}

func decodeRepeated(value string) string {
	decoded := value
	for i := 0; i < 2; i++ {
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	return decoded
}

func httpHeaderName(name string) string {
	parts := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(name)), func(r rune) bool {
		return r == '-' || r == '_'
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, "-")
}

func flattenHeaders(headers http.Header) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(strings.Join(headers.Values(key), ","))
		builder.WriteString(" ")
	}
	return strings.TrimSpace(builder.String())
}

func flattenHeaderNames(headers http.Header) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, " ")
}

func flattenArgs(args map[string][]string) string {
	if len(args) == 0 {
		return ""
	}
	var builder strings.Builder
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := args[key]
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(strings.Join(values, ","))
		builder.WriteString(" ")
	}
	return strings.TrimSpace(builder.String())
}

func flattenArgNames(args map[string][]string) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, " ")
}

func parsedFieldValues(parsed requestparser.ParsedRequest, variable string) (string, []string) {
	values := make([]string, 0, 2)
	evidence := make([]string, 0, 2)
	for _, field := range parsed.Fields {
		if field.Variable != variable {
			continue
		}
		values = append(values, field.NormalizedValue)
		evidence = append(evidence, fmt.Sprintf("%s=%s", variable, truncateEvidence(field.NormalizedValue)))
	}
	return strings.Join(values, ","), evidence
}

func argValues(args map[string][]string, name string) (string, []string) {
	values, ok := args[name]
	if !ok || len(values) == 0 {
		return "", nil
	}
	evidence := make([]string, 0, len(values))
	for _, value := range values {
		evidence = append(evidence, fmt.Sprintf("ARGS:%s=%s", name, truncateEvidence(value)))
	}
	return strings.Join(values, ","), evidence
}

func compareNumeric(operator, target, pattern string) bool {
	left, err := strconv.ParseFloat(strings.TrimSpace(target), 64)
	if err != nil {
		return false
	}
	right, err := strconv.ParseFloat(strings.TrimSpace(pattern), 64)
	if err != nil {
		return false
	}
	switch operator {
	case "@gt":
		return left > right
	case "@ge":
		return left >= right
	case "@lt":
		return left < right
	case "@le":
		return left <= right
	case "@eq":
		return left == right
	default:
		return false
	}
}

func truncateEvidence(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 160 {
		return value
	}
	return value[:160]
}

func uniqueEvidence(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
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
	case strings.Contains(name, "xxe") || strings.Contains(name, "906"):
		return "xxe"
	case strings.Contains(name, "upload") || strings.Contains(name, "907"):
		return "upload"
	case strings.Contains(name, "protocol") || strings.Contains(name, "909"):
		return "protocol"
	case strings.Contains(name, "api") || strings.Contains(name, "graphql") || strings.Contains(name, "jwt") || strings.Contains(name, "json") || strings.Contains(name, "910"):
		return "api"
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

package accesscontrol

import (
	"context"
	"net"
	"path"
	"strings"

	"aegis-waf/internal/database"
)

type Decision string

const (
	DecisionNone          Decision = "none"
	DecisionBlock         Decision = "block"
	DecisionSkipDetection Decision = "skip_detection"
	DecisionAllow         Decision = "allow"
)

type Request struct {
	SiteID    uint
	SourceIP  net.IP
	Path      string
	Args      map[string][]string
	Headers   map[string][]string
	Method    string
	UserAgent string
}

type Result struct {
	Decision Decision
	Rule     database.AccessRule
	Reason   string
}

type RuleProvider interface {
	ListAccessRules(context.Context) ([]database.AccessRule, error)
}

type Evaluator struct{ rules []database.AccessRule }

func NewEvaluator(rules []database.AccessRule) *Evaluator { return &Evaluator{rules: rules} }

func (e *Evaluator) Evaluate(req Request) Result {
	for _, rule := range e.rules {
		if !rule.Enabled || (rule.SiteID != 0 && rule.SiteID != req.SiteID) {
			continue
		}
		switch rule.Type {
		case database.AccessRuleIPBlacklist:
			if ipMatches(req.SourceIP, rule.Value) {
				return Result{Decision: DecisionBlock, Rule: rule, Reason: "ip blacklist matched"}
			}
		case database.AccessRuleIPWhitelist, database.AccessRuleCIDRWhitelist:
			if ipMatches(req.SourceIP, rule.Value) {
				return Result{Decision: DecisionSkipDetection, Rule: rule, Reason: "ip whitelist matched"}
			}
		case database.AccessRuleURLWhitelist:
			if pathMatches(req.Path, rule.Value) {
				return Result{Decision: DecisionAllow, Rule: rule, Reason: "url whitelist matched"}
			}
		case database.AccessRuleParamWhitelist:
			if paramMatches(req.Args, rule.Value) {
				return Result{Decision: DecisionSkipDetection, Rule: rule, Reason: "param whitelist matched"}
			}
		case database.AccessRuleHeaderWhitelist:
			if headerMatches(req.Headers, rule.Value) {
				return Result{Decision: DecisionSkipDetection, Rule: rule, Reason: "header whitelist matched"}
			}
		case database.AccessRuleCookieWhitelist:
			if cookieMatches(headerValue(req.Headers, "Cookie"), rule.Value) {
				return Result{Decision: DecisionSkipDetection, Rule: rule, Reason: "cookie whitelist matched"}
			}
		case database.AccessRuleUABlacklist:
			if strings.Contains(strings.ToLower(req.UserAgent), strings.ToLower(rule.Value)) {
				return Result{Decision: DecisionBlock, Rule: rule, Reason: "user-agent blacklist matched"}
			}
		case database.AccessRuleMethodBlock:
			if strings.EqualFold(req.Method, rule.Value) {
				return Result{Decision: DecisionBlock, Rule: rule, Reason: "method block matched"}
			}
		}
	}
	return Result{Decision: DecisionNone}
}

func ipMatches(ip net.IP, value string) bool {
	value = strings.TrimSpace(value)
	if ip == nil || value == "" {
		return false
	}
	if strings.Contains(value, "/") {
		_, cidr, err := net.ParseCIDR(value)
		return err == nil && cidr.Contains(ip)
	}
	return ip.Equal(net.ParseIP(value))
}

func pathMatches(requestPath, pattern string) bool {
	requestPath = strings.Split(requestPath, "?")[0]
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if ok, _ := path.Match(pattern, requestPath); ok {
		return true
	}
	return requestPath == pattern || strings.HasPrefix(requestPath, strings.TrimSuffix(pattern, "*"))
}

func paramMatches(args map[string][]string, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(args) == 0 {
		return false
	}
	parts := strings.SplitN(value, "=", 2)
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return false
	}
	values, ok := args[name]
	if !ok {
		return false
	}
	if len(parts) == 1 || strings.TrimSpace(parts[1]) == "" {
		return true
	}
	expected := strings.TrimSpace(parts[1])
	for _, actual := range values {
		if actual == expected {
			return true
		}
	}
	return false
}

func headerMatches(headers map[string][]string, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(headers) == 0 {
		return false
	}
	parts := strings.SplitN(value, "=", 2)
	name := strings.ToLower(strings.TrimSpace(parts[0]))
	if name == "" {
		return false
	}
	expected := ""
	if len(parts) > 1 {
		expected = strings.TrimSpace(parts[1])
	}
	vals := headerValues(headers, name)
	if len(vals) == 0 {
		return false
	}
	if expected == "" {
		return true
	}
	for _, actual := range vals {
		if actual == expected || strings.Contains(actual, expected) {
			return true
		}
	}
	return false
}

func headerValues(headers map[string][]string, name string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	for key, vals := range headers {
		if strings.ToLower(strings.TrimSpace(key)) == name {
			return vals
		}
	}
	return nil
}

func headerValue(headers map[string][]string, name string) string {
	return strings.Join(headerValues(headers, name), "; ")
}

func cookieMatches(cookieHeader, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.TrimSpace(cookieHeader) == "" {
		return false
	}
	parts := strings.SplitN(value, "=", 2)
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return false
	}
	for _, cookie := range strings.Split(cookieHeader, ";") {
		key, val, ok := strings.Cut(strings.TrimSpace(cookie), "=")
		if !ok || strings.TrimSpace(key) != name {
			continue
		}
		if len(parts) == 1 || strings.TrimSpace(parts[1]) == "" || val == strings.TrimSpace(parts[1]) {
			return true
		}
	}
	return false
}

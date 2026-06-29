package detection

import (
	"context"
	"net/http"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionBlock Decision = "block"
)

type RuleAction string

const (
	RuleActionDeny RuleAction = "deny"
	RuleActionLog  RuleAction = "log"
	RuleActionPass RuleAction = "pass"
)

type Rule struct {
	ID       int
	Phase    int
	Group    string
	Variable string
	Operator string
	Pattern  string
	Action   RuleAction
	Message  string
	Severity string
	Score    int
	Source   string
	Enabled  bool
}

type Request struct {
	Method            string
	URI               string
	Headers           http.Header
	Body              string
	Args              map[string][]string
	EnabledRuleGroups map[string]bool
}

type MatchedRule struct {
	ID       int
	Message  string
	Source   string
	Group    string
	Action   RuleAction
	Severity string
	Score    int
	Evidence []string
}

type Result struct {
	Decision Decision
	Matches  []MatchedRule
	Score    int
	Severity string
}

type Engine interface {
	Start(context.Context) error
	Stop(context.Context) error
	Reload(context.Context) error
	Inspect(context.Context, Request) (Result, error)
	Rules() []Rule
	EnableRule(int) error
	DisableRule(int) error
}

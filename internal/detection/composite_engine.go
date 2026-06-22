package detection

import "context"

type RuntimeRuleEngine interface {
	Engine
	UpsertRuntimeRule(Rule) error
	DeleteRuntimeRule(int) error
}

type CompositeEngine struct {
	primary  Engine
	runtime  RuntimeRuleEngine
	failOpen bool
}

func NewCompositeEngine(primary Engine, runtime RuntimeRuleEngine, failOpen bool) *CompositeEngine {
	return &CompositeEngine{primary: primary, runtime: runtime, failOpen: failOpen}
}

func (e *CompositeEngine) Start(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if e.primary != nil {
		if err := e.primary.Start(ctx); err != nil {
			return err
		}
	}
	if e.runtime != nil {
		return e.runtime.Start(ctx)
	}
	return nil
}

func (e *CompositeEngine) Stop(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if e.primary != nil {
		_ = e.primary.Stop(ctx)
	}
	if e.runtime != nil {
		return e.runtime.Stop(ctx)
	}
	return nil
}

func (e *CompositeEngine) Reload(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if e.primary != nil {
		if err := e.primary.Reload(ctx); err != nil && !e.failOpen {
			return err
		}
	}
	if e.runtime != nil {
		return e.runtime.Reload(ctx)
	}
	return nil
}

func (e *CompositeEngine) Inspect(ctx context.Context, req Request) (Result, error) {
	result := Result{Decision: DecisionAllow}
	if e == nil {
		return result, nil
	}
	if e.primary != nil {
		primary, err := e.primary.Inspect(ctx, req)
		if err != nil && !e.failOpen {
			return primary, err
		}
		result = mergeResults(result, primary)
	}
	if e.runtime != nil {
		runtime, err := e.runtime.Inspect(ctx, req)
		if err != nil {
			return mergeResults(result, runtime), err
		}
		result = mergeResults(result, runtime)
	}
	return result, nil
}

func (e *CompositeEngine) Rules() []Rule {
	if e == nil {
		return nil
	}
	var out []Rule
	if e.primary != nil {
		out = append(out, e.primary.Rules()...)
	}
	if e.runtime != nil {
		out = append(out, e.runtime.Rules()...)
	}
	return out
}

func (e *CompositeEngine) EnableRule(id int) error {
	if e == nil || e.runtime == nil {
		return nil
	}
	return e.runtime.EnableRule(id)
}

func (e *CompositeEngine) DisableRule(id int) error {
	if e == nil || e.runtime == nil {
		return nil
	}
	return e.runtime.DisableRule(id)
}

func (e *CompositeEngine) UpsertRuntimeRule(rule Rule) error {
	if e == nil || e.runtime == nil {
		return nil
	}
	return e.runtime.UpsertRuntimeRule(rule)
}

func (e *CompositeEngine) DeleteRuntimeRule(id int) error {
	if e == nil || e.runtime == nil {
		return nil
	}
	return e.runtime.DeleteRuntimeRule(id)
}

func mergeResults(left, right Result) Result {
	out := left
	if out.Decision == "" {
		out.Decision = DecisionAllow
	}
	out.Matches = append(out.Matches, right.Matches...)
	out.Score += right.Score
	out.Severity = maxSeverity(out.Severity, right.Severity)
	if right.Decision == DecisionBlock {
		out.Decision = DecisionBlock
	}
	return out
}

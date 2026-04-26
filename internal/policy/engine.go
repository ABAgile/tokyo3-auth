package policy

// Engine evaluates a set of Rules against a PolicyContext.
type Engine struct {
	rules []Rule
}

// New returns an Engine loaded with the given rules.
func New(rules ...Rule) *Engine {
	return &Engine{rules: rules}
}

// AddRule appends a rule to the engine.
func (e *Engine) AddRule(r Rule) { e.rules = append(e.rules, r) }

// Evaluate runs all rules and returns every violation found.
func (e *Engine) Evaluate(ctx PolicyContext) []PolicyViolation {
	var violations []PolicyViolation
	for _, r := range e.rules {
		if v := r.Evaluate(ctx); v != nil {
			violations = append(violations, *v)
		}
	}
	return violations
}

// First returns the first violation, or nil if all rules pass.
func (e *Engine) First(ctx PolicyContext) *PolicyViolation {
	for _, r := range e.rules {
		if v := r.Evaluate(ctx); v != nil {
			return v
		}
	}
	return nil
}

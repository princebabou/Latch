// Package enforce combines policy rules and deterministic risk signals.
package enforce

import (
	"github.com/latch-security/latch/internal/policy"
	"github.com/latch-security/latch/internal/risk"
	"github.com/latch-security/latch/pkg/models"
)

// Evaluate creates the final fail-safe verdict. Explicit BLOCK and ALLOW rules
// win. REQUIRE_APPROVAL is a minimum control, so it cannot weaken a critical
// risk signal into a merely approved action.
func Evaluate(config policy.Config, action models.Action) models.Assessment {
	policyResult := policy.Evaluate(config, action)
	score, signals := risk.Analyze(action)
	assessment := models.Assessment{Decision: policyResult.Decision, RiskScore: score, RiskLevel: risk.Level(score), Signals: signals}
	hasBlock, hasAllow, hasApproval := false, false, false
	for _, rule := range policyResult.Rules {
		assessment.TriggeredRules = append(assessment.TriggeredRules, rule.ID)
		if rule.Description != "" {
			assessment.Reasons = append(assessment.Reasons, rule.Description)
		}
		switch rule.Action {
		case models.DecisionBlock:
			hasBlock = true
		case models.DecisionAllow:
			hasAllow = true
		case models.DecisionRequireApproval:
			hasApproval = true
		}
	}
	switch {
	case hasBlock:
		assessment.Decision = models.DecisionBlock
	case hasAllow:
		assessment.Decision = models.DecisionAllow
	case score >= config.Enforcement.BlockThreshold:
		assessment.Decision = models.DecisionBlock
		assessment.Reasons = append(assessment.Reasons, "Risk score exceeds the configured block threshold")
	case hasApproval || score >= config.Enforcement.ApprovalThreshold:
		assessment.Decision = models.DecisionRequireApproval
		if !hasApproval {
			assessment.Reasons = append(assessment.Reasons, "Risk score exceeds the configured approval threshold")
		}
	default:
		assessment.Decision = models.DecisionAllow
	}
	return assessment
}

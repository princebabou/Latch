// Package enforce combines policy rules and deterministic risk signals.
package enforce

import (
	"fmt"
	"strings"

	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/internal/risk"
	"github.com/princebabou/Latch/pkg/models"
)

// Evaluate creates the final fail-safe verdict. Explicit blocks and identity
// ceilings win; approval and allow rules cannot weaken a critical risk signal.
func Evaluate(config policy.Config, action models.Action) models.Assessment {
	return EvaluateWithIdentity(config, action, models.IdentityContext{
		ID: action.AgentID, Verified: false, Source: "self_asserted",
	})
}

// CanonicalizeIdentity maps a registered alias to its stable agent ID without
// hiding a mismatch between the trusted context and the action payload.
func CanonicalizeIdentity(config policy.Config, action models.Action, identity models.IdentityContext) (models.Action, models.IdentityContext) {
	canonicalIdentity, identityKnown := policy.CanonicalAgentID(config, identity.ID)
	canonicalAction, actionKnown := policy.CanonicalAgentID(config, action.AgentID)
	if identityKnown && strings.TrimSpace(action.AgentID) == "" {
		identity.ID = canonicalIdentity
		action.AgentID = canonicalIdentity
		return action, identity
	}
	if identityKnown && actionKnown && strings.EqualFold(canonicalIdentity, canonicalAction) {
		identity.ID = canonicalIdentity
		action.AgentID = canonicalAction
	}
	return action, identity
}

// EvaluateWithIdentity applies the same policy and risk contract while keeping
// transport-authenticated identity outside the untrusted Action payload.
func EvaluateWithIdentity(config policy.Config, action models.Action, identity models.IdentityContext) models.Assessment {
	if strings.TrimSpace(identity.ID) == "" {
		identity.ID = action.AgentID
	}
	if strings.TrimSpace(identity.Source) == "" {
		identity.Source = "self_asserted"
	}
	action, identity = CanonicalizeIdentity(config, action, identity)
	policyResult := policy.Evaluate(config, action)
	identityResult := policy.AuthorizeIdentity(config, identity, action)
	score, signals := risk.Analyze(action)
	hardDenyNames := risk.HardDeny(signals)
	protectedRisk := len(hardDenyNames) > 0 || score >= config.Enforcement.BlockThreshold
	assessment := models.Assessment{
		Decision:            models.DecisionAllow,
		RiskScore:           score,
		RiskLevel:           risk.Level(score),
		HardDeny:            len(hardDenyNames) > 0,
		Signals:             signals,
		IdentityVerified:    identity.Verified,
		IdentitySource:      identity.Source,
		CanonicalAgentID:    identityResult.CanonicalAgentID,
		MatchedCapabilities: identityResult.MatchedCapabilities,
	}
	hasBlock, hasAllow, hasApproval := false, false, false
	var unsafeOverrideRules []string
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
			if rule.UnsafeOverride {
				unsafeOverrideRules = append(unsafeOverrideRules, rule.ID)
			}
		case models.DecisionRequireApproval:
			hasApproval = true
		}
	}
	switch {
	case hasBlock:
		assessment.Decision = models.DecisionBlock
		assessment.DecisionSource = "policy_block"
	case !identityResult.Allowed:
		assessment.Decision = models.DecisionBlock
		assessment.DecisionSource = identityResult.DecisionSource
		assessment.Reasons = append(assessment.Reasons, identityResult.Reason)
	case protectedRisk && len(unsafeOverrideRules) == 0:
		assessment.Decision = models.DecisionBlock
		if assessment.HardDeny {
			assessment.DecisionSource = "hard_deny"
			assessment.Reasons = append(assessment.Reasons, fmt.Sprintf("Built-in hard-deny signals cannot be bypassed by ordinary allow rules: %s", strings.Join(hardDenyNames, ", ")))
		} else {
			assessment.DecisionSource = "risk_block_threshold"
			assessment.Reasons = append(assessment.Reasons, "Critical aggregate risk cannot be bypassed by an ordinary allow rule")
		}
	case hasApproval:
		assessment.Decision = models.DecisionRequireApproval
		assessment.DecisionSource = "policy_approval"
	case protectedRisk && len(unsafeOverrideRules) > 0:
		assessment.Decision = models.DecisionAllow
		assessment.DecisionSource = "unsafe_override"
		assessment.UnsafeOverride = true
		assessment.Reasons = append(assessment.Reasons, fmt.Sprintf("Break-glass override applied by policy rule: %s", strings.Join(unsafeOverrideRules, ", ")))
	case hasAllow:
		assessment.Decision = models.DecisionAllow
		assessment.DecisionSource = "policy_allow"
	case score >= config.Enforcement.ApprovalThreshold:
		assessment.Decision = models.DecisionRequireApproval
		assessment.DecisionSource = "risk_approval_threshold"
		assessment.Reasons = append(assessment.Reasons, "Risk score exceeds the configured approval threshold")
	default:
		assessment.Decision = models.DecisionAllow
		assessment.DecisionSource = "default_allow"
	}
	return assessment
}

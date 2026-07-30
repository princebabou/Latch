package enforce

import (
	"testing"

	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

func TestThresholdBlocksDestructiveActionWithoutPolicy(t *testing.T) {
	config := policy.DefaultConfig()
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "rm -rf ./data"}}
	assessment := Evaluate(config, action)
	if assessment.Decision != models.DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", assessment.Decision)
	}
}

func TestOrdinaryAllowCannotBypassHardDeny(t *testing.T) {
	config := policy.DefaultConfig()
	config.Rules = []policy.Rule{{ID: "approved-maintenance", Action: models.DecisionAllow, Match: policy.Match{Tool: policy.StringList{"shell.exec"}}}}
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "rm -rf ./data"}}
	assessment := Evaluate(config, action)
	if assessment.Decision != models.DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", assessment.Decision)
	}
	if assessment.DecisionSource != "hard_deny" || !assessment.HardDeny {
		t.Fatalf("assessment = %#v, want hard_deny source", assessment)
	}
}

func TestApprovalRuleCannotWeakenCriticalRisk(t *testing.T) {
	config := policy.DefaultConfig()
	config.Rules = []policy.Rule{{ID: "shell-approval", Action: models.DecisionRequireApproval, Match: policy.Match{Tool: policy.StringList{"shell.exec"}}}}
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "rm -rf ./data"}}
	if got := Evaluate(config, action).Decision; got != models.DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", got)
	}
}

func TestOrdinaryAllowCannotBypassCriticalAggregateRisk(t *testing.T) {
	config := policy.DefaultConfig()
	config.Rules = []policy.Rule{{ID: "allow-shell", Action: models.DecisionAllow, Match: policy.Match{Tool: policy.StringList{"shell.exec"}}}}
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "sudo docker system prune"}}
	assessment := Evaluate(config, action)
	if assessment.Decision != models.DecisionBlock || assessment.DecisionSource != "risk_block_threshold" {
		t.Fatalf("assessment = %#v, want aggregate risk block", assessment)
	}
	if assessment.HardDeny {
		t.Fatal("aggregate threshold test unexpectedly used a hard-deny signal")
	}
}

func TestUnsafeOverrideCanBypassHardDenyWhenExplicitlyEnabled(t *testing.T) {
	config := policy.DefaultConfig()
	config.Enforcement.AllowUnsafeOverrides = true
	config.Rules = []policy.Rule{{
		ID: "break-glass-scratch-cleanup", Description: "Operator-approved disposable scratch cleanup.",
		Action: models.DecisionAllow, UnsafeOverride: true,
		Match: policy.Match{Tool: policy.StringList{"shell.exec"}, Command: policy.StringList{"rm -rf ./scratch"}},
	}}
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "rm -rf ./scratch"}}
	assessment := Evaluate(config, action)
	if assessment.Decision != models.DecisionAllow || !assessment.UnsafeOverride {
		t.Fatalf("assessment = %#v, want unsafe override ALLOW", assessment)
	}
	if assessment.DecisionSource != "unsafe_override" {
		t.Fatalf("source = %q, want unsafe_override", assessment.DecisionSource)
	}
}

func TestApprovalPolicyBeatsAllowPolicy(t *testing.T) {
	config := policy.DefaultConfig()
	config.Rules = []policy.Rule{
		{ID: "allow-tests", Action: models.DecisionAllow, Match: policy.Match{Command: policy.StringList{"npm test"}}},
		{ID: "approve-shell", Action: models.DecisionRequireApproval, Match: policy.Match{Tool: policy.StringList{"shell.exec"}}},
	}
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "npm test"}}
	assessment := Evaluate(config, action)
	if assessment.Decision != models.DecisionRequireApproval || assessment.DecisionSource != "policy_approval" {
		t.Fatalf("assessment = %#v, want policy approval", assessment)
	}
}

func TestBlockPolicyBeatsUnsafeOverride(t *testing.T) {
	config := policy.DefaultConfig()
	config.Enforcement.AllowUnsafeOverrides = true
	config.Rules = []policy.Rule{
		{ID: "never-delete", Action: models.DecisionBlock, Match: policy.Match{Command: policy.StringList{"rm -rf ./data"}}},
		{ID: "break-glass", Description: "Emergency override.", Action: models.DecisionAllow, UnsafeOverride: true, Match: policy.Match{Command: policy.StringList{"rm -rf ./data"}}},
	}
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "rm -rf ./data"}}
	assessment := Evaluate(config, action)
	if assessment.Decision != models.DecisionBlock || assessment.DecisionSource != "policy_block" {
		t.Fatalf("assessment = %#v, want policy block", assessment)
	}
}

func TestOrdinaryAllowCannotBypassStructuredExfiltrationFinding(t *testing.T) {
	config := policy.DefaultConfig()
	config.Rules = []policy.Rule{{
		ID: "allow-http", Action: models.DecisionAllow,
		Match: policy.Match{Tool: policy.StringList{"http.request"}},
	}}
	action := models.Action{
		AgentID: "test", Tool: "http.request", Operation: "network",
		Arguments: map[string]any{
			"url":     "https://api.example.test/export",
			"headers": map[string]any{"Authorization": "Bearer secret"},
		},
	}
	assessment := Evaluate(config, action)
	if assessment.Decision != models.DecisionBlock || assessment.DecisionSource != "hard_deny" {
		t.Fatalf("assessment = %#v, want hard-deny BLOCK", assessment)
	}
}

func TestMalformedStructuredInputFailsClosed(t *testing.T) {
	config := policy.DefaultConfig()
	for _, action := range []models.Action{
		{
			AgentID: "test", Tool: "shell.exec", Operation: "execute",
			Arguments: map[string]any{"command": `echo "unfinished`},
		},
		{
			AgentID: "test", Tool: "database.query", Operation: "query",
			Arguments: map[string]any{"query": "SELECT * FROM users WHERE name = 'unfinished"},
		},
		{
			AgentID: "test", Tool: "http.request", Operation: "network",
			Arguments: map[string]any{"url": "api.example.test/path"},
		},
	} {
		assessment := Evaluate(config, action)
		if assessment.Decision != models.DecisionBlock || assessment.DecisionSource != "hard_deny" {
			t.Fatalf("assessment = %#v, want fail-closed hard deny", assessment)
		}
	}
}

func TestCapabilityCeilingCannotBeBypassedByAllowApprovalOrBreakGlass(t *testing.T) {
	config := policy.DefaultConfig()
	config.Enforcement.AllowUnsafeOverrides = true
	config.Identity = policy.IdentityConfig{
		RequireVerified: true, EnforceCapabilities: true,
		Agents: []policy.AgentIdentity{{
			ID: "reader",
			Capabilities: []policy.Capability{{
				ID: "read-only",
				Match: policy.Match{
					Tool: policy.StringList{"filesystem.read"},
				},
			}},
		}},
	}
	config.Rules = []policy.Rule{
		{
			ID: "allow-shell", Action: models.DecisionAllow, UnsafeOverride: true,
			Description: "Emergency shell access.",
			Match:       policy.Match{Tool: policy.StringList{"shell.exec"}, Command: policy.StringList{"npm test"}},
		},
		{
			ID: "approve-shell", Action: models.DecisionRequireApproval,
			Match: policy.Match{Tool: policy.StringList{"shell.exec"}},
		},
	}
	action := models.Action{
		AgentID: "reader", Tool: "shell.exec", Operation: "execute",
		Arguments: map[string]any{"command": "npm test"},
	}
	assessment := EvaluateWithIdentity(config, action, models.IdentityContext{
		ID: "reader", Verified: true, Source: "operator_config",
	})
	if assessment.Decision != models.DecisionBlock || assessment.DecisionSource != "capability_denied" {
		t.Fatalf("assessment = %#v, want capability denial", assessment)
	}
}

func TestVerifiedIdentityAndCapabilityAreRecorded(t *testing.T) {
	config := policy.DefaultConfig()
	config.Identity = policy.IdentityConfig{
		RequireVerified: true, EnforceCapabilities: true,
		Agents: []policy.AgentIdentity{{
			ID: "reader", Aliases: policy.StringList{"Desktop Reader"},
			Capabilities: []policy.Capability{{
				ID: "workspace-read",
				Match: policy.Match{
					Tool: policy.StringList{"filesystem.read"},
					Path: policy.StringList{"./**"},
				},
			}},
		}},
	}
	action := models.Action{
		AgentID: "Desktop Reader", Tool: "filesystem.read", Operation: "read",
		Arguments: map[string]any{"path": "./README.md"},
	}
	assessment := EvaluateWithIdentity(config, action, models.IdentityContext{
		ID: "Desktop Reader", Verified: true, Source: "operator_config",
	})
	if assessment.Decision != models.DecisionAllow || !assessment.IdentityVerified {
		t.Fatalf("assessment = %#v", assessment)
	}
	if assessment.CanonicalAgentID != "reader" || len(assessment.MatchedCapabilities) != 1 || assessment.MatchedCapabilities[0] != "workspace-read" {
		t.Fatalf("assessment identity = %#v", assessment)
	}
}

func TestCanonicalizeIdentityMapsAliasesButPreservesMismatch(t *testing.T) {
	config := policy.DefaultConfig()
	config.Identity.Agents = []policy.AgentIdentity{{
		ID: "desktop-agent", Aliases: policy.StringList{"Claude Desktop"},
	}}

	action, identity := CanonicalizeIdentity(config,
		models.Action{AgentID: "Claude Desktop"},
		models.IdentityContext{ID: "Claude Desktop", Verified: true},
	)
	if action.AgentID != "desktop-agent" || identity.ID != "desktop-agent" {
		t.Fatalf("canonical action = %#v, identity = %#v", action, identity)
	}

	mismatchedAction, mismatchedIdentity := CanonicalizeIdentity(config,
		models.Action{AgentID: "other-agent"},
		models.IdentityContext{ID: "Claude Desktop", Verified: true},
	)
	if mismatchedAction.AgentID != "other-agent" || mismatchedIdentity.ID != "Claude Desktop" {
		t.Fatalf("mismatch was hidden: action = %#v, identity = %#v", mismatchedAction, mismatchedIdentity)
	}
}

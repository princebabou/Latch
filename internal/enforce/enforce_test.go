package enforce

import (
	"testing"

	"github.com/latch-security/latch/internal/policy"
	"github.com/latch-security/latch/pkg/models"
)

func TestThresholdBlocksDestructiveActionWithoutPolicy(t *testing.T) {
	config := policy.DefaultConfig()
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "rm -rf ./data"}}
	assessment := Evaluate(config, action)
	if assessment.Decision != models.DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", assessment.Decision)
	}
}

func TestExplicitPolicyTakesPrecedenceOverThreshold(t *testing.T) {
	config := policy.DefaultConfig()
	config.Rules = []policy.Rule{{ID: "approved-maintenance", Action: models.DecisionAllow, Match: policy.Match{Tool: policy.StringList{"shell.exec"}}}}
	action := models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "rm -rf ./data"}}
	if got := Evaluate(config, action).Decision; got != models.DecisionAllow {
		t.Fatalf("decision = %s, want ALLOW", got)
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

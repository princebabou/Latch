package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/latch-security/latch/pkg/models"
)

func TestEvaluateBlockOverridesApproval(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{
		{ID: "approve-shell", Action: models.DecisionRequireApproval, Match: Match{Tool: StringList{"shell.exec"}}},
		{ID: "block-keys", Action: models.DecisionBlock, Match: Match{Path: StringList{"**/*.pem"}}},
	}
	action := models.Action{Tool: "shell.exec", Arguments: map[string]any{"path": "certs/prod.pem"}}
	result := Evaluate(config, action)
	if result.Decision != models.DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", result.Decision)
	}
	if len(result.Rules) != 2 {
		t.Fatalf("matched %d rules, want 2", len(result.Rules))
	}
}

func TestPolicyMatchesScalarArgumentAndDoubleStar(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{ID: "prod", Action: models.DecisionRequireApproval, Match: Match{Path: StringList{"**/.env"}, Arguments: map[string]StringList{"environment": {"production"}}}}}
	action := models.Action{Arguments: map[string]any{"path": "services/api/.env", "environment": "production"}}
	if got := Evaluate(config, action).Decision; got != models.DecisionRequireApproval {
		t.Fatalf("decision = %s, want REQUIRE_APPROVAL", got)
	}
}

func TestValidateRejectsDuplicateIDs(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{ID: "same", Action: models.DecisionAllow, Match: Match{Tool: StringList{"read"}}}, {ID: "same", Action: models.DecisionAllow, Match: Match{Tool: StringList{"write"}}}}
	if err := config.Validate(); err == nil {
		t.Fatal("expected duplicate rule validation error")
	}
}

func TestLoadNormalizesLowercaseYAMLDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	contents := "rules:\n  - id: no-keys\n    match:\n      path: '**/*.key'\n    action: block\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Rules[0].Action; got != models.DecisionBlock {
		t.Fatalf("action = %s, want BLOCK", got)
	}
}

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/princebabou/Latch/pkg/models"
)

func TestParseRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	base := `version: 1
enforcement:
  approval_threshold: 40
  block_threshold: 90
approvals:
  store_path: approvals.json
  default_ttl: 15m
  max_ttl: 24h
  lock_timeout: 2s
budgets:
  store_path: budgets.json
  lock_timeout: 2s
audit:
  path: audit.jsonl
`
	for name, document := range map[string]string{
		"unknown":  base + "mystery_control: true\n",
		"multiple": base + "---\n" + base,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(document), t.TempDir()); err == nil {
				t.Fatal("unsafe policy document was accepted")
			} else if name == "unknown" && !strings.Contains(err.Error(), "field mystery_control") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

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

func TestValidateRejectsUnsafeOverrideWhenGloballyDisabled(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{
		ID: "break-glass", Description: "Emergency cleanup.", Action: models.DecisionAllow, UnsafeOverride: true,
		Match: Match{Command: StringList{"rm -rf ./scratch"}},
	}}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "allow_unsafe_overrides") {
		t.Fatalf("error = %v, want global opt-in validation error", err)
	}
}

func TestValidateRejectsBroadUnsafeOverride(t *testing.T) {
	config := DefaultConfig()
	config.Enforcement.AllowUnsafeOverrides = true
	config.Rules = []Rule{{
		ID: "break-glass", Description: "Overly broad override.", Action: models.DecisionAllow, UnsafeOverride: true,
		Match: Match{Tool: StringList{"shell.exec"}},
	}}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "must match a path") {
		t.Fatalf("error = %v, want resource-specific validation error", err)
	}
}

func TestValidateAcceptsSpecificUnsafeOverride(t *testing.T) {
	config := DefaultConfig()
	config.Enforcement.AllowUnsafeOverrides = true
	config.Rules = []Rule{{
		ID: "break-glass", Description: "Emergency cleanup of disposable scratch data.", Action: models.DecisionAllow, UnsafeOverride: true,
		Match: Match{Tool: StringList{"shell.exec"}, Command: StringList{"rm -rf ./scratch"}},
	}}
	if err := config.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestDigestChangesWithSecurityPolicyButNotAuditDestination(t *testing.T) {
	base := DefaultConfig()
	first, err := Digest(base)
	if err != nil {
		t.Fatal(err)
	}
	auditChanged := base
	auditChanged.Audit.Path = "somewhere-else/audit.jsonl"
	second, err := Digest(auditChanged)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("audit destination unexpectedly changed policy digest")
	}
	policyChanged := base
	policyChanged.Enforcement.BlockThreshold = 91
	third, err := Digest(policyChanged)
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("security policy change did not change digest")
	}
	approvalChanged := base
	approvalChanged.Approvals.MaxTTL = Duration(12 * time.Hour)
	fourth, err := Digest(approvalChanged)
	if err != nil {
		t.Fatal(err)
	}
	if first == fourth {
		t.Fatal("approval TTL policy change did not change digest")
	}
}

func TestLoadResolvesOperationalStateRelativeToPolicyFile(t *testing.T) {
	configDirectory := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDirectory, "latch.yaml")
	content := `version: 1
identity:
  require_verified: false
budgets:
  store_path: state/budgets.json
  lock_timeout: 2s
  rules: []
approvals:
  store_path: state/approvals.json
audit:
  path: state/audit.jsonl
rules: []
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"audit":     config.Audit.Path,
		"approvals": config.Approvals.StorePath,
		"budgets":   config.Budgets.StorePath,
	} {
		if !filepath.IsAbs(path) || filepath.Dir(filepath.Dir(path)) != configDirectory {
			t.Fatalf("%s path = %q, want config-relative absolute path", name, path)
		}
	}
}

func TestValidateApprovalDurations(t *testing.T) {
	config := DefaultConfig()
	config.Approvals.DefaultTTL = Duration(25 * time.Hour)
	if err := config.Validate(); err == nil {
		t.Fatal("expected approval TTL validation error")
	}
}

func TestDatabaseOperationPolicyUsesStructuredSQLParser(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{
		ID: "approve-updates", Action: models.DecisionRequireApproval,
		Match: Match{DatabaseOperation: StringList{"UPDATE"}},
	}}
	for _, query := range []string{
		"-- leading comment\nUPDATE users SET active = true WHERE id = 1",
		"WITH changed AS (UPDATE users SET active = true WHERE id = 1 RETURNING id) SELECT id FROM changed",
		"SELECT 1; UPDATE users SET active = true WHERE id = 1",
	} {
		action := models.Action{Tool: "database.query", Operation: "query", Arguments: map[string]any{"query": query}}
		result := Evaluate(config, action)
		if result.Decision != models.DecisionRequireApproval {
			t.Fatalf("query %q decision = %s, want REQUIRE_APPROVAL", query, result.Decision)
		}
	}
}

func TestDatabaseOperationPolicyIgnoresKeywordsInSQLData(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{
		ID: "block-drop", Action: models.DecisionBlock,
		Match: Match{DatabaseOperation: StringList{"DROP"}},
	}}
	action := models.Action{
		Tool: "database.query", Operation: "query",
		Arguments: map[string]any{"query": "SELECT 'DROP TABLE users' AS example"},
	}
	if result := Evaluate(config, action); result.Decision != models.DecisionAllow {
		t.Fatalf("decision = %s, want ALLOW", result.Decision)
	}
}

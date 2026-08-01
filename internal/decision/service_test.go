package decision

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/princebabou/Latch/internal/approval"
	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

func TestServiceAppliesPolicyApprovalAndAudit(t *testing.T) {
	config := testConfig(t)
	logger := &memoryLogger{}
	service, err := New(config, logger, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := service.Decide(models.Action{AgentID: "desktop-agent", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "npm test"}}, models.IdentityContext{ID: "desktop-agent", Verified: true, Source: "test"})
	if result.Assessment.Decision != models.DecisionRequireApproval || result.Approval != "pending" {
		t.Fatalf("result = %#v", result)
	}
	if len(logger.events) != 1 || logger.events[0].Assessment.Decision != models.DecisionRequireApproval {
		t.Fatalf("events = %#v", logger.events)
	}
}

func TestServiceUsesExactDurableApproval(t *testing.T) {
	config := testConfig(t)
	store, err := approval.NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	action := models.Action{AgentID: "desktop-agent", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "npm test"}}
	if _, err := store.Issue(action, "operator:test", time.Minute); err != nil {
		t.Fatal(err)
	}
	service, err := New(config, &memoryLogger{}, &store, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := service.Decide(action, models.IdentityContext{ID: "desktop-agent", Verified: true, Source: "test"})
	if result.Assessment.Decision != models.DecisionAllow || result.Assessment.DecisionSource != "approval_cache" {
		t.Fatalf("assessment = %#v", result.Assessment)
	}
}

func TestServiceFailsClosedWhenAuditFails(t *testing.T) {
	config := testConfig(t)
	service, err := New(config, failingLogger{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := service.Decide(models.Action{AgentID: "desktop-agent", Tool: "filesystem.read", Operation: "read", Arguments: map[string]any{"path": "./README.md"}}, models.IdentityContext{ID: "desktop-agent", Verified: true, Source: "test"})
	if result.Assessment.Decision != models.DecisionBlock || result.Assessment.DecisionSource != "audit_failure" || result.OperationalError == nil {
		t.Fatalf("result = %#v", result)
	}
}

func testConfig(t *testing.T) policy.Config {
	t.Helper()
	config := policy.DefaultConfig()
	state := t.TempDir()
	config.Audit.Path = filepath.Join(state, "audit.jsonl")
	config.Audit.Terminal = false
	config.Approvals.StorePath = filepath.Join(state, "approvals.json")
	config.Budgets.StorePath = filepath.Join(state, "budgets.json")
	config.Identity.RequireVerified = true
	config.Identity.Agents = []policy.AgentIdentity{{ID: "desktop-agent"}}
	config.Rules = []policy.Rule{{ID: "approve-shell", Match: policy.Match{Tool: policy.StringList{"shell.exec"}}, Action: models.DecisionRequireApproval}}
	return config
}

type memoryLogger struct{ events []models.AuditEvent }

func (m *memoryLogger) Write(event models.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

type failingLogger struct{}

func (failingLogger) Write(models.AuditEvent) error { return fmt.Errorf("unavailable") }

var _ audit.Logger = (*memoryLogger)(nil)
var _ audit.Logger = failingLogger{}

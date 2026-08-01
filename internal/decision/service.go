// Package decision implements Latch's transport-neutral pre-execution service.
package decision

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/approval"
	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/budget"
	"github.com/princebabou/Latch/internal/enforce"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

// Service owns the shared enforcement dependencies used by every adapter.
type Service struct {
	Policy        policy.Config
	AuditLogger   audit.Logger
	ApprovalStore *approval.Store
	BudgetStore   *budget.Store
}

// Result contains the canonical action and complete security decision.
// OperationalError is safe for diagnostics; the assessment has already failed
// closed when it is non-nil.
type Result struct {
	Action           models.Action
	Assessment       models.Assessment
	Approval         string
	Event            models.AuditEvent
	OperationalError error
}

// New constructs a service with durable policy-bound stores.
func New(config policy.Config, logger audit.Logger, approvalStore *approval.Store, budgetStore *budget.Store) (*Service, error) {
	if logger == nil {
		logger = audit.JSONLLogger{Path: config.Audit.Path}
	}
	if approvalStore == nil {
		store, err := approval.NewStore(config)
		if err != nil {
			return nil, fmt.Errorf("configure approval store: %w", err)
		}
		approvalStore = &store
	}
	if budgetStore == nil {
		store, err := budget.NewStore(config)
		if err != nil {
			return nil, fmt.Errorf("configure action budgets: %w", err)
		}
		budgetStore = &store
	}
	return &Service{Policy: config, AuditLogger: logger, ApprovalStore: approvalStore, BudgetStore: budgetStore}, nil
}

// Decide applies identity, policy, risk, approval, budget, and audit controls
// in their security precedence order. An ALLOW result consumes matching budget
// capacity because callers invoke this immediately before execution.
func (s *Service) Decide(action models.Action, identity models.IdentityContext) Result {
	action, identity = enforce.CanonicalizeIdentity(s.Policy, action, identity)
	assessment := enforce.EvaluateWithIdentity(s.Policy, action, identity)
	approvalStatus := ""
	var operationalErr error

	if assessment.Decision != models.DecisionBlock {
		statuses, err := s.BudgetStore.Check(action)
		assessment = budget.Apply(assessment, statuses, err)
		if err != nil {
			operationalErr = errors.Join(operationalErr, fmt.Errorf("check action budget: %w", err))
		}
	}
	if assessment.Decision == models.DecisionRequireApproval {
		grant, allowed, err := s.ApprovalStore.IsAllowed(action)
		switch {
		case err != nil:
			assessment.Decision = models.DecisionBlock
			assessment.DecisionSource = "approval_store_failure"
			assessment.Reasons = append(assessment.Reasons, "Approval state could not be read safely")
			approvalStatus = "store_error"
			operationalErr = errors.Join(operationalErr, fmt.Errorf("read approval store: %w", err))
		case allowed:
			assessment.Decision = models.DecisionAllow
			assessment.DecisionSource = "approval_cache"
			assessment.Reasons = append(assessment.Reasons, fmt.Sprintf("Approved by %s until %s", grant.Approver, grant.ExpiresAt.Format(time.RFC3339)))
			approvalStatus = "grant:" + grant.ID
		default:
			approvalStatus = "pending"
		}
	}
	if assessment.Decision == models.DecisionAllow {
		statuses, err := s.BudgetStore.Reserve(action)
		assessment = budget.Apply(assessment, statuses, err)
		if err != nil {
			operationalErr = errors.Join(operationalErr, fmt.Errorf("reserve action budget: %w", err))
		}
	}

	event := audit.NewEvent(action, assessment, approvalStatus)
	if err := s.AuditLogger.Write(event); err != nil {
		assessment.Decision = models.DecisionBlock
		assessment.DecisionSource = "audit_failure"
		assessment.Reasons = append(assessment.Reasons, "Required audit logging failed")
		operationalErr = errors.Join(operationalErr, fmt.Errorf("write audit event: %w", err))
		event = audit.NewEvent(action, assessment, approvalStatus)
	}
	return Result{Action: action, Assessment: assessment, Approval: approvalStatus, Event: event, OperationalError: operationalErr}
}

// Diagnostic summarizes an operational failure without action arguments or
// other potentially sensitive request data.
func Diagnostic(result Result) string {
	if result.OperationalError == nil {
		return ""
	}
	source := strings.TrimSpace(result.Assessment.DecisionSource)
	if source == "" {
		source = "enforcement_failure"
	}
	return "Latch: " + source + "; action blocked"
}

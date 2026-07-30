// Package models contains the protocol-neutral types shared by Latch.
package models

import "time"

// Action is a normalized request from an AI agent to an external capability.
// It deliberately does not contain any MCP-specific fields so the policy engine
// can be reused by API, browser, database, and shell integrations.
type Action struct {
	AgentID   string         `json:"agent_id"`
	Tool      string         `json:"tool"`
	Operation string         `json:"operation"`
	Resource  string         `json:"resource,omitempty"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// IdentityContext is transport-authenticated context supplied by a trusted
// adapter. It is deliberately separate from Action.Metadata, which may contain
// untrusted protocol input.
type IdentityContext struct {
	ID       string `json:"id"`
	Verified bool   `json:"verified"`
	Source   string `json:"source"`
}

// Decision is the outcome that must be enforced before an action is executed.
type Decision string

const (
	DecisionAllow           Decision = "ALLOW"
	DecisionBlock           Decision = "BLOCK"
	DecisionRequireApproval Decision = "REQUIRE_APPROVAL"
)

// RiskSignal makes the score explainable to an operator and to downstream logs.
type RiskSignal struct {
	Name        string `json:"name"`
	Score       int    `json:"score"`
	Description string `json:"description"`
}

// BudgetStatus explains current state for one cumulative action limit.
type BudgetStatus struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description,omitempty"`
	Limit       int    `json:"limit"`
	Used        int    `json:"used"`
	Remaining   int    `json:"remaining"`
	Window      string `json:"window"`
	RetryAfter  string `json:"retry_after,omitempty"`
	Exceeded    bool   `json:"exceeded"`
}

// Assessment is the complete pre-execution security verdict.
type Assessment struct {
	Decision            Decision       `json:"decision"`
	DecisionSource      string         `json:"decision_source"`
	RiskScore           int            `json:"risk_score"`
	RiskLevel           string         `json:"risk_level"`
	HardDeny            bool           `json:"hard_deny"`
	UnsafeOverride      bool           `json:"unsafe_override,omitempty"`
	IdentityVerified    bool           `json:"identity_verified"`
	IdentitySource      string         `json:"identity_source,omitempty"`
	CanonicalAgentID    string         `json:"canonical_agent_id,omitempty"`
	MatchedCapabilities []string       `json:"matched_capabilities,omitempty"`
	Budgets             []BudgetStatus `json:"budgets,omitempty"`
	Signals             []RiskSignal   `json:"signals,omitempty"`
	TriggeredRules      []string       `json:"triggered_rules,omitempty"`
	Reasons             []string       `json:"reasons,omitempty"`
}

// AuditEvent is a durable, redacted record of one enforcement decision.
type AuditEvent struct {
	Timestamp  time.Time  `json:"timestamp"`
	Action     Action     `json:"action"`
	Assessment Assessment `json:"assessment"`
	Approval   string     `json:"approval,omitempty"`
}

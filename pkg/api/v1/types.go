// Package v1 defines the stable Latch enforcement API contract.
package v1

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/princebabou/Latch/pkg/models"
)

const (
	// APIVersion is embedded in every request and response so incompatible
	// contract changes fail explicitly instead of being silently ignored.
	APIVersion = "latch.security/v1"
	// MediaType is the versioned representation used by HTTP integrations.
	MediaType = "application/vnd.latch.decision.v1+json"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)

// Action is the stable wire representation of an intended tool action.
type Action struct {
	AgentID   string         `json:"agent_id,omitempty"`
	Tool      string         `json:"tool"`
	Operation string         `json:"operation,omitempty"`
	Resource  string         `json:"resource,omitempty"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// DecisionRequest asks Latch for one pre-execution decision. RequestID is an
// idempotency key: replaying it is rejected rather than replaying an ALLOW.
type DecisionRequest struct {
	APIVersion string `json:"api_version"`
	RequestID  string `json:"request_id"`
	Action     Action `json:"action"`
}

// Risk contains deterministic scoring evidence.
type Risk struct {
	Score   int                 `json:"score"`
	Level   string              `json:"level"`
	Signals []models.RiskSignal `json:"signals,omitempty"`
}

// Identity reports only transport-established identity state. Request
// metadata can never turn an identity into a verified one.
type Identity struct {
	Verified            bool     `json:"verified"`
	Source              string   `json:"source,omitempty"`
	CanonicalAgentID    string   `json:"canonical_agent_id,omitempty"`
	MatchedCapabilities []string `json:"matched_capabilities,omitempty"`
}

// PolicyResult explains the winning control and every relevant rule.
type PolicyResult struct {
	DecisionSource string   `json:"decision_source"`
	HardDeny       bool     `json:"hard_deny"`
	UnsafeOverride bool     `json:"unsafe_override,omitempty"`
	TriggeredRules []string `json:"triggered_rules,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
}

// DecisionResponse is returned with HTTP 200 for ALLOW, BLOCK, and
// REQUIRE_APPROVAL. Clients must execute only an explicit ALLOW.
type DecisionResponse struct {
	APIVersion string                `json:"api_version"`
	RequestID  string                `json:"request_id"`
	Decision   models.Decision       `json:"decision"`
	FailClosed bool                  `json:"fail_closed,omitempty"`
	Risk       Risk                  `json:"risk"`
	Identity   Identity              `json:"identity"`
	Policy     PolicyResult          `json:"policy"`
	Budgets    []models.BudgetStatus `json:"budgets,omitempty"`
}

// Error describes a contract or transport error. It never represents an
// enforcement verdict; valid verdicts always use DecisionResponse.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	APIVersion string `json:"api_version"`
	RequestID  string `json:"request_id,omitempty"`
	Error      Error  `json:"error"`
}

func (r DecisionRequest) Validate() error {
	if r.APIVersion != APIVersion {
		return fmt.Errorf("api_version must be %q", APIVersion)
	}
	if !requestIDPattern.MatchString(r.RequestID) {
		return fmt.Errorf("request_id must be 8-128 safe ASCII characters")
	}
	if strings.TrimSpace(r.Action.Tool) == "" {
		return fmt.Errorf("action.tool is required")
	}
	if len(r.Action.Tool) > 256 {
		return fmt.Errorf("action.tool cannot exceed 256 bytes")
	}
	if len(r.Action.AgentID) > 256 {
		return fmt.Errorf("action.agent_id cannot exceed 256 bytes")
	}
	if len(r.Action.Operation) > 128 {
		return fmt.Errorf("action.operation cannot exceed 128 bytes")
	}
	if len(r.Action.Resource) > 16<<10 {
		return fmt.Errorf("action.resource cannot exceed 16384 bytes")
	}
	return nil
}

// NewRequestID returns a cryptographically random idempotency key.
func NewRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return "req_" + hex.EncodeToString(value[:]), nil
}

// Response converts the internal assessment to the stable v1 wire contract.
func Response(requestID string, assessment models.Assessment, failClosed bool) DecisionResponse {
	return DecisionResponse{
		APIVersion: APIVersion,
		RequestID:  requestID,
		Decision:   assessment.Decision,
		FailClosed: failClosed,
		Risk:       Risk{Score: assessment.RiskScore, Level: assessment.RiskLevel, Signals: assessment.Signals},
		Identity: Identity{
			Verified: assessment.IdentityVerified, Source: assessment.IdentitySource,
			CanonicalAgentID: assessment.CanonicalAgentID, MatchedCapabilities: assessment.MatchedCapabilities,
		},
		Policy: PolicyResult{
			DecisionSource: assessment.DecisionSource, HardDeny: assessment.HardDeny,
			UnsafeOverride: assessment.UnsafeOverride, TriggeredRules: assessment.TriggeredRules,
			Reasons: assessment.Reasons,
		},
		Budgets: assessment.Budgets,
	}
}

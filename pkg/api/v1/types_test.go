package v1

import (
	"testing"

	"github.com/princebabou/Latch/pkg/models"
)

func TestDecisionRequestValidation(t *testing.T) {
	valid := DecisionRequest{APIVersion: APIVersion, RequestID: "req_12345678", Action: Action{Tool: "filesystem.read"}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DecisionRequest){
		"version":    func(request *DecisionRequest) { request.APIVersion = "v2" },
		"request id": func(request *DecisionRequest) { request.RequestID = "short" },
		"tool":       func(request *DecisionRequest) { request.Action.Tool = " " },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestResponsePreservesDecisionEvidence(t *testing.T) {
	assessment := models.Assessment{
		Decision: models.DecisionBlock, DecisionSource: "policy_block", RiskScore: 98, RiskLevel: "CRITICAL",
		HardDeny: true, IdentityVerified: true, CanonicalAgentID: "agent", TriggeredRules: []string{"deny-key"},
	}
	response := Response("req_12345678", assessment, false)
	if response.APIVersion != APIVersion || response.Decision != models.DecisionBlock || response.Policy.DecisionSource != "policy_block" || !response.Policy.HardDeny {
		t.Fatalf("response = %#v", response)
	}
}

func TestNewRequestIDIsValidAndUnique(t *testing.T) {
	first, err := NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !requestIDPattern.MatchString(first) || !requestIDPattern.MatchString(second) {
		t.Fatalf("ids = %q, %q", first, second)
	}
}

package enforcementapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/princebabou/Latch/internal/decision"
	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	testDecisionToken = "0123456789abcdef0123456789abcdef"
	testApproverToken = "fedcba9876543210fedcba9876543210"
)

func TestPendingDecisionCarriesApprovalFingerprint(t *testing.T) {
	handler, _ := testHandler(t, Options{AgentID: "desktop-agent"})
	pending := requestDecision(t, handler, "req_pendingfp1", api.Action{Tool: "shell.exec", Arguments: map[string]any{"command": "npm test"}}, nil)
	var response api.DecisionResponse
	decodeResponse(t, pending, &response)
	if response.Decision != models.DecisionRequireApproval {
		t.Fatalf("decision = %s", response.Decision)
	}
	if response.Approval == nil || response.Approval.Status != "pending" || len(response.Approval.Fingerprint) != 64 {
		t.Fatalf("approval challenge = %#v", response.Approval)
	}
}

func TestRemoteApprovalGrantAllowsRetry(t *testing.T) {
	handler, _ := testHandler(t, Options{
		AgentID: "desktop-agent", BearerToken: testDecisionToken, ApproverToken: testApproverToken,
	})
	auth := map[string]string{"Authorization": "Bearer " + testDecisionToken}
	action := api.Action{Tool: "shell.exec", Arguments: map[string]any{"command": "npm test"}}

	pending := requestDecision(t, handler, "req_flow0001", action, auth)
	var pendingResponse api.DecisionResponse
	decodeResponse(t, pending, &pendingResponse)
	if pendingResponse.Decision != models.DecisionRequireApproval || pendingResponse.Approval == nil {
		t.Fatalf("expected pending with challenge, got %#v", pendingResponse)
	}

	granted := issueApproval(t, handler, testApproverToken, approvalRequest{
		APIVersion: api.APIVersion, Approver: "alice", TTLSeconds: 300, Action: action,
	})
	if granted.Code != http.StatusCreated {
		t.Fatalf("grant status = %d, body = %s", granted.Code, granted.Body.String())
	}

	allowed := requestDecision(t, handler, "req_flow0002", action, auth)
	var allowedResponse api.DecisionResponse
	decodeResponse(t, allowed, &allowedResponse)
	if allowedResponse.Decision != models.DecisionAllow || allowedResponse.Policy.DecisionSource != "approval_cache" {
		t.Fatalf("expected allow via approval cache, got %#v", allowedResponse)
	}
}

func TestApprovalEndpointRequiresSeparateToken(t *testing.T) {
	handler, _ := testHandler(t, Options{
		AgentID: "desktop-agent", BearerToken: testDecisionToken, ApproverToken: testApproverToken,
	})
	action := api.Action{Tool: "shell.exec", Arguments: map[string]any{"command": "npm test"}}

	// The decision bearer token must not be able to self-approve.
	withDecisionToken := issueApproval(t, handler, testDecisionToken, approvalRequest{
		APIVersion: api.APIVersion, Approver: "alice", Action: action,
	})
	if withDecisionToken.Code != http.StatusUnauthorized {
		t.Fatalf("decision token approval status = %d", withDecisionToken.Code)
	}

	withApproverToken := issueApproval(t, handler, testApproverToken, approvalRequest{
		APIVersion: api.APIVersion, Approver: "alice", Action: action,
	})
	if withApproverToken.Code != http.StatusCreated {
		t.Fatalf("approver token status = %d, body = %s", withApproverToken.Code, withApproverToken.Body.String())
	}
}

func TestApprovalEndpointDisabledWithoutApproverToken(t *testing.T) {
	handler, _ := testHandler(t, Options{AgentID: "desktop-agent", BearerToken: testDecisionToken})
	response := issueApproval(t, handler, testDecisionToken, approvalRequest{
		APIVersion: api.APIVersion, Approver: "alice",
		Action: api.Action{Tool: "shell.exec", Arguments: map[string]any{"command": "npm test"}},
	})
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled approvals status = %d", response.Code)
	}
}

func TestApproverTokenMustDifferFromBearer(t *testing.T) {
	service, err := decision.New(apiTestConfig(t), &memoryLogger{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Service: service, BearerToken: testDecisionToken, ApproverToken: testDecisionToken}); err == nil {
		t.Fatal("expected error when approver token equals bearer token")
	}
}

func TestApprovalListReturnsGrants(t *testing.T) {
	handler, _ := testHandler(t, Options{
		AgentID: "desktop-agent", BearerToken: testDecisionToken, ApproverToken: testApproverToken,
	})
	action := api.Action{Tool: "shell.exec", Arguments: map[string]any{"command": "npm test"}}
	issueApproval(t, handler, testApproverToken, approvalRequest{APIVersion: api.APIVersion, Approver: "alice", Action: action})

	request := httptest.NewRequest(http.MethodGet, "/v1/approvals", nil)
	request.Header.Set("Authorization", "Bearer "+testApproverToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list status = %d", response.Code)
	}
	var body struct {
		Grants []map[string]any `json:"grants"`
	}
	decodeResponse(t, response, &body)
	if len(body.Grants) != 1 {
		t.Fatalf("grants = %#v", body.Grants)
	}
}

func issueApproval(t *testing.T, handler http.Handler, token string, request approvalRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/v1/approvals", bytes.NewReader(body))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	return response
}

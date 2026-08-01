package enforcementapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/policy"
	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

func TestDecisionAPIAllowsAndBlocksWithStableContract(t *testing.T) {
	handler, logger := testHandler(t, Options{AgentID: "desktop-agent"})

	allowed := requestDecision(t, handler, "req_allowed1", api.Action{Tool: "filesystem.read", Arguments: map[string]any{"path": "./README.md"}}, nil)
	if allowed.Code != http.StatusOK {
		t.Fatalf("allow status = %d, body = %s", allowed.Code, allowed.Body.String())
	}
	var allowResponse api.DecisionResponse
	decodeResponse(t, allowed, &allowResponse)
	if allowResponse.APIVersion != api.APIVersion || allowResponse.Decision != models.DecisionAllow || !allowResponse.Identity.Verified {
		t.Fatalf("allow response = %#v", allowResponse)
	}

	blocked := requestDecision(t, handler, "req_blocked1", api.Action{Tool: "filesystem.read", Arguments: map[string]any{"path": "~/.ssh/id_rsa"}}, nil)
	var blockResponse api.DecisionResponse
	decodeResponse(t, blocked, &blockResponse)
	if blocked.Code != http.StatusOK || blockResponse.Decision != models.DecisionBlock || blockResponse.Policy.DecisionSource != "policy_block" {
		t.Fatalf("block response = %#v, status = %d", blockResponse, blocked.Code)
	}
	pending := requestDecision(t, handler, "req_pending1", api.Action{Tool: "shell.exec", Arguments: map[string]any{"command": "npm test"}}, nil)
	var pendingResponse api.DecisionResponse
	decodeResponse(t, pending, &pendingResponse)
	if pending.Code != http.StatusOK || pendingResponse.Decision != models.DecisionRequireApproval || pendingResponse.Policy.DecisionSource != "policy_approval" {
		t.Fatalf("pending response = %#v, status = %d", pendingResponse, pending.Code)
	}
	if len(logger.events) != 3 {
		t.Fatalf("events = %#v", logger.events)
	}
	if logger.events[0].Action.Metadata["request_id"] != "req_allowed1" {
		t.Fatalf("audit metadata = %#v", logger.events[0].Action.Metadata)
	}
}

func TestDecisionAPIRejectsReplayUnknownFieldsAndOversize(t *testing.T) {
	handler, _ := testHandler(t, Options{AgentID: "desktop-agent", MaxBodyBytes: 1024})
	first := requestDecision(t, handler, "req_replay01", api.Action{Tool: "filesystem.read"}, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d", first.Code)
	}
	second := requestDecision(t, handler, "req_replay01", api.Action{Tool: "filesystem.read"}, nil)
	if second.Code != http.StatusConflict {
		t.Fatalf("replay status = %d", second.Code)
	}

	unknown := httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewBufferString(`{"api_version":"latch.security/v1","request_id":"req_unknown1","action":{"tool":"x"},"trusted":true}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", unknownResponse.Code)
	}

	oversizedBody, err := json.Marshal(api.DecisionRequest{
		APIVersion: api.APIVersion, RequestID: "req_oversize1",
		Action: api.Action{Tool: "filesystem.read", Metadata: map[string]any{"padding": string(make([]byte, 2048))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	oversized := httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(oversizedBody))
	oversized.Header.Set("Content-Type", "application/json")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status = %d, body = %s", oversizedResponse.Code, oversizedResponse.Body.String())
	}
}

func TestDecisionAPIFailsClosedWhenReplayProtectionIsAtCapacity(t *testing.T) {
	handler, _ := testHandler(t, Options{AgentID: "desktop-agent", ReplayLimit: 1})
	if first := requestDecision(t, handler, "req_capacity1", api.Action{Tool: "filesystem.read"}, nil); first.Code != http.StatusOK {
		t.Fatalf("first status = %d", first.Code)
	}
	second := requestDecision(t, handler, "req_capacity2", api.Action{Tool: "filesystem.read"}, nil)
	if second.Code != http.StatusServiceUnavailable || second.Header().Get("Retry-After") == "" {
		t.Fatalf("capacity status = %d, headers = %#v", second.Code, second.Header())
	}
}

func TestDecisionAPIAuthOriginAndIdentityBoundaries(t *testing.T) {
	handler, _ := testHandler(t, Options{BearerToken: "correct-token-with-at-least-32-bytes", AllowedOrigins: []string{"https://console.example"}})
	unauthorized := requestDecision(t, handler, "req_unauth01", api.Action{AgentID: "desktop-agent", Tool: "filesystem.read"}, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
	forbidden := requestDecision(t, handler, "req_origin01", api.Action{AgentID: "desktop-agent", Tool: "filesystem.read"}, map[string]string{
		"Authorization": "Bearer correct-token-with-at-least-32-bytes", "Origin": "https://evil.example",
	})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("origin status = %d", forbidden.Code)
	}
	unverified := requestDecision(t, handler, "req_unverif1", api.Action{AgentID: "desktop-agent", Tool: "filesystem.read"}, map[string]string{
		"Authorization": "Bearer correct-token-with-at-least-32-bytes", "Origin": "https://console.example",
	})
	var response api.DecisionResponse
	decodeResponse(t, unverified, &response)
	if response.Decision != models.DecisionBlock || response.Policy.DecisionSource != "identity_unverified" || response.Identity.Verified {
		t.Fatalf("response = %#v", response)
	}
}

func TestDecisionAPIRejectsWeakTokensAndInvalidOrigins(t *testing.T) {
	service, err := decision.New(apiTestConfig(t), &memoryLogger{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Service: service, BearerToken: "too-short"}); err == nil {
		t.Fatal("weak bearer token was accepted")
	}
	for _, origin := range []string{"*", "file://local", "https://example.test/path", "https://user@example.test"} {
		if _, err := New(Options{Service: service, AllowedOrigins: []string{origin}}); err == nil {
			t.Errorf("invalid origin %q was accepted", origin)
		}
	}
}

func TestDecisionAPIFailsClosedWhenAuditUnavailable(t *testing.T) {
	config := apiTestConfig(t)
	service, err := decision.New(config, failingLogger{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{Service: service, AgentID: "desktop-agent"})
	if err != nil {
		t.Fatal(err)
	}
	result := requestDecision(t, handler, "req_audit001", api.Action{Tool: "filesystem.read"}, nil)
	var response api.DecisionResponse
	decodeResponse(t, result, &response)
	if result.Code != http.StatusOK || response.Decision != models.DecisionBlock || !response.FailClosed || response.Policy.DecisionSource != "audit_failure" {
		t.Fatalf("response = %#v", response)
	}
}

func testHandler(t *testing.T, options Options) (*Handler, *memoryLogger) {
	t.Helper()
	logger := &memoryLogger{}
	service, err := decision.New(apiTestConfig(t), logger, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options.Service = service
	handler, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return handler, logger
}

func apiTestConfig(t *testing.T) policy.Config {
	t.Helper()
	config := policy.DefaultConfig()
	state := t.TempDir()
	config.Audit.Path = filepath.Join(state, "audit.jsonl")
	config.Audit.Terminal = false
	config.Approvals.StorePath = filepath.Join(state, "approvals.json")
	config.Budgets.StorePath = filepath.Join(state, "budgets.json")
	config.Identity.RequireVerified = true
	config.Identity.Agents = []policy.AgentIdentity{{ID: "desktop-agent"}}
	config.Rules = []policy.Rule{
		{ID: "block-private-key", Match: policy.Match{Path: policy.StringList{"~/.ssh/**"}}, Action: models.DecisionBlock},
		{ID: "approve-shell", Match: policy.Match{Tool: policy.StringList{"shell.exec"}}, Action: models.DecisionRequireApproval},
	}
	return config
}

func requestDecision(t *testing.T, handler http.Handler, requestID string, action api.Action, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(api.DecisionRequest{APIVersion: api.APIVersion, RequestID: requestID, Action: action})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(body))
	request.Header.Set("Content-Type", api.MediaType)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, response.Body.String())
	}
}

type memoryLogger struct{ events []models.AuditEvent }

func (logger *memoryLogger) Write(event models.AuditEvent) error {
	logger.events = append(logger.events, event)
	return nil
}

type failingLogger struct{}

func (failingLogger) Write(models.AuditEvent) error { return fmt.Errorf("unavailable") }

var _ audit.Logger = (*memoryLogger)(nil)
var _ audit.Logger = failingLogger{}

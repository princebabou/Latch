package playground

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	api "github.com/princebabou/Latch/pkg/api/v1"
)

const testPolicy = `version: 1
identity:
  require_verified: true
  agents:
    - id: desktop-agent
rules:
  - id: block-production
    description: Production writes are blocked.
    match:
      tool: deployment.apply
      arguments:
        environment: production
    action: block
`

func TestPlaygroundEvaluatesActualPolicyWithoutExecution(t *testing.T) {
	handler := newTestHandler(t)
	verified := true
	request := EvaluateRequest{
		PolicyYAML: testPolicy,
		Action:     apiAction("deployment.apply", map[string]any{"environment": "production"}),
		Identity:   IdentityInput{ID: "desktop-agent", Verified: &verified},
	}
	response := evaluateRequest(t, handler, request, true)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result EvaluateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Evaluation.Assessment.Decision != "BLOCK" || result.Evaluation.Assessment.DecisionSource != "policy_block" {
		t.Fatalf("assessment = %#v", result.Evaluation.Assessment)
	}
	if len(result.Evaluation.MatchedRules) != 1 || result.Evaluation.MatchedRules[0].ID != "block-production" {
		t.Fatalf("matched rules = %#v", result.Evaluation.MatchedRules)
	}
	if len(result.Notices) < 2 || !strings.Contains(result.Notices[0], "No tool") {
		t.Fatalf("notices = %#v", result.Notices)
	}
}

func TestPlaygroundComparesPolicyWeakening(t *testing.T) {
	handler := newTestHandler(t)
	verified := true
	edited := strings.Replace(testPolicy, "action: block", "action: allow", 1)
	request := EvaluateRequest{
		PolicyYAML: edited, BaselinePolicyYAML: testPolicy,
		Action:   apiAction("deployment.apply", map[string]any{"environment": "production"}),
		Identity: IdentityInput{ID: "desktop-agent", Verified: &verified},
	}
	response := evaluateRequest(t, handler, request, true)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result EvaluateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Delta == nil || !result.Delta.Changed || !result.Delta.Weakened || result.Delta.From != "BLOCK" || result.Delta.To != "ALLOW" {
		t.Fatalf("delta = %#v", result.Delta)
	}
}

func TestPlaygroundRejectsCrossSiteTokenlessAndAmbiguousRequests(t *testing.T) {
	handler := newTestHandler(t)
	verified := true
	valid := EvaluateRequest{PolicyYAML: testPolicy, Action: apiAction("safe.tool", nil), Identity: IdentityInput{ID: "desktop-agent", Verified: &verified}}

	if response := evaluateRequest(t, handler, valid, false); response.Code != http.StatusForbidden {
		t.Fatalf("tokenless status = %d", response.Code)
	}
	payload, _ := json.Marshal(valid)
	crossSite := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/evaluate", bytes.NewReader(payload))
	crossSite.Header.Set("Content-Type", "application/json")
	crossSite.Header.Set("X-Latch-Playground-Token", "test-token")
	crossSite.Header.Set("Origin", "https://attacker.example")
	crossResponse := httptest.NewRecorder()
	handler.ServeHTTP(crossResponse, crossSite)
	if crossResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-site status = %d", crossResponse.Code)
	}

	ambiguous := []byte(`{"policy_yaml":"` + strings.ReplaceAll(testPolicy, "\n", `\n`) + `","action":{"tool":"safe.tool","tool":"unsafe.tool"},"identity":{"id":"desktop-agent","verified":true}}`)
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/evaluate", bytes.NewReader(ambiguous))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Latch-Playground-Token", "test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_json") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPlaygroundBootstrapAndStaticAssetsHaveSecurityHeaders(t *testing.T) {
	handler := newTestHandler(t)
	for _, path := range []string{"/", "/app.css", "/app.js", "/api/bootstrap"} {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("path=%s status=%d headers=%#v", path, response.Code, response.Header())
		}
	}
}

func TestPlaygroundEvaluationLeavesOperationalStateUntouched(t *testing.T) {
	directory := t.TempDir()
	handler, err := New(Options{PolicyYAML: testPolicy, PolicyDirectory: directory, AgentID: "desktop-agent", Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	verified := true
	response := evaluateRequest(t, handler, EvaluateRequest{
		PolicyYAML: testPolicy, Action: apiAction("safe.tool", nil),
		Identity: IdentityInput{ID: "desktop-agent", Verified: &verified},
	}, true)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("playground wrote operational state: %#v", entries)
	}
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	handler, err := New(Options{PolicyYAML: testPolicy, PolicyDirectory: t.TempDir(), AgentID: "desktop-agent", Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func evaluateRequest(t *testing.T, handler *Handler, input EvaluateRequest, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/evaluate", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if authenticated {
		request.Header.Set("X-Latch-Playground-Token", "test-token")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func apiAction(tool string, arguments map[string]any) api.Action {
	return api.Action{Tool: tool, Arguments: arguments}
}

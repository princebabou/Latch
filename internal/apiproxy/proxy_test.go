package apiproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

const testGatewayToken = "0123456789abcdef0123456789abcdef"

func TestHandlerForwardsOnlyAfterAllowWithSeparatedCredentials(t *testing.T) {
	logger := &memoryLogger{}
	service := testService(t, logger)
	var captured *http.Request
	var capturedBody []byte
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		captured = request.Clone(request.Context())
		capturedBody, _ = io.ReadAll(request.Body)
		return response(http.StatusCreated, `{"created":true}`, nil), nil
	})}
	handler, err := New(Options{
		Service: service, AgentID: "api-agent", UpstreamURL: "https://api.example.test/base",
		GatewayToken: testGatewayToken, UpstreamHeaders: http.Header{"Authorization": {"Bearer operator-secret"}},
		ForwardSensitiveHeaders: true, HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "http://latch.local/v1/items?sort=asc", strings.NewReader(`{"name":"Ada"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Latch-Token", testGatewayToken)
	request.Header.Set("Authorization", "Bearer agent-secret")
	request.Header.Set("X-Request-Id", "req-1")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated || recorder.Header().Get("X-Latch-Decision") != "ALLOW" {
		t.Fatalf("status = %d, headers = %#v, body = %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if captured == nil || captured.URL.String() != "https://api.example.test/base/v1/items?sort=asc" {
		t.Fatalf("upstream request = %#v", captured)
	}
	if captured.Header.Get("Authorization") != "Bearer operator-secret" || captured.Header.Get("X-Latch-Token") != "" {
		t.Fatalf("upstream headers = %#v", captured.Header)
	}
	if string(capturedBody) != `{"name":"Ada"}` {
		t.Fatalf("upstream body = %q", capturedBody)
	}
	if len(logger.events) != 1 || logger.events[0].Assessment.Decision != models.DecisionAllow {
		t.Fatalf("events = %#v", logger.events)
	}
	encoded, _ := json.Marshal(logger.events[0])
	if bytes.Contains(encoded, []byte("operator-secret")) || bytes.Contains(encoded, []byte("agent-secret")) {
		t.Fatalf("audit event leaked a credential: %s", encoded)
	}
}

func TestHandlerBlocksPolicyDecisionWithoutCallingUpstream(t *testing.T) {
	service := testService(t, &memoryLogger{}, policy.Rule{
		ID: "deny-delete", Match: policy.Match{Tool: policy.StringList{"http.request"}, HTTPMethod: policy.StringList{"DELETE"}}, Action: models.DecisionBlock,
	})
	calls := 0
	handler := testHandler(t, service, func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusOK, `{}`, nil), nil
	})
	request := httptest.NewRequest(http.MethodDelete, "http://latch.local/v1/items/1", nil)
	request.Header.Set("X-Latch-Token", testGatewayToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || calls != 0 || !strings.Contains(recorder.Body.String(), `"code":"blocked"`) {
		t.Fatalf("status = %d, calls = %d, body = %s", recorder.Code, calls, recorder.Body.String())
	}
}

func TestHandlerRequiresApprovalForOpaqueBody(t *testing.T) {
	service := testService(t, &memoryLogger{})
	calls := 0
	handler := testHandler(t, service, func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusOK, `{}`, nil), nil
	})
	request := httptest.NewRequest(http.MethodPost, "http://latch.local/upload", strings.NewReader("binary-ish"))
	request.Header.Set("X-Latch-Token", testGatewayToken)
	request.Header.Set("Content-Type", "application/octet-stream")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPreconditionRequired || calls != 0 || !strings.Contains(recorder.Body.String(), `"code":"approval_required"`) {
		t.Fatalf("status = %d, calls = %d, body = %s", recorder.Code, calls, recorder.Body.String())
	}
}

func TestHandlerConsumesExactDurableApproval(t *testing.T) {
	service := testService(t, &memoryLogger{}, policy.Rule{
		ID: "approve-read", Match: policy.Match{Tool: policy.StringList{"http.request"}}, Action: models.DecisionRequireApproval,
	})
	action := models.Action{
		AgentID: "api-agent", Tool: "http.request", Operation: "network", Resource: "api.example.test",
		Arguments: map[string]any{"method": "GET", "url": "https://api.example.test/v1"},
	}
	if _, err := service.ApprovalStore.Issue(action, "operator:test", 0); err != nil {
		t.Fatal(err)
	}
	calls := 0
	handler := testHandler(t, service, func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusOK, `{}`, nil), nil
	})
	request := requestWithToken(http.MethodGet, "http://latch.local/v1", "", "")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || calls != 1 {
		t.Fatalf("status = %d, calls = %d, body = %s", recorder.Code, calls, recorder.Body.String())
	}
}

func TestHandlerFailsClosedWhenRequiredAuditIsUnavailable(t *testing.T) {
	service := testService(t, failingLogger{})
	calls := 0
	handler := testHandler(t, service, func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusOK, `{}`, nil), nil
	})
	request := requestWithToken(http.MethodGet, "http://latch.local/v1", "", "")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || calls != 0 || !strings.Contains(recorder.Body.String(), `"code":"enforcement_unavailable"`) {
		t.Fatalf("status = %d, calls = %d, body = %s", recorder.Code, calls, recorder.Body.String())
	}
}

func TestHandlerReservesBudgetBeforeForwarding(t *testing.T) {
	config := testPolicy(t)
	config.Budgets.Rules = []policy.BudgetRule{{
		ID: "one-request", Match: policy.Match{Tool: policy.StringList{"http.request"}},
		MaxActions: 1, Window: policy.Duration(time.Minute),
	}}
	service, err := decision.New(config, &memoryLogger{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	handler := testHandler(t, service, func(*http.Request) (*http.Response, error) {
		calls++
		return response(http.StatusOK, `{}`, nil), nil
	})
	for attempt, status := range []int{http.StatusOK, http.StatusTooManyRequests} {
		request := requestWithToken(http.MethodGet, "http://latch.local/v1", "", "")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != status {
			t.Fatalf("attempt %d status = %d, want %d; body = %s", attempt+1, recorder.Code, status, recorder.Body.String())
		}
		if status == http.StatusTooManyRequests && recorder.Header().Get("Retry-After") == "" {
			t.Fatal("budget denial omitted Retry-After")
		}
	}
	if calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls)
	}
}

func TestHandlerRejectsBoundaryBypassesBeforeForwarding(t *testing.T) {
	service := testService(t, &memoryLogger{})
	tests := []struct {
		name    string
		request *http.Request
		status  int
	}{
		{
			name: "missing token", request: httptest.NewRequest(http.MethodGet, "http://latch.local/v1", nil),
			status: http.StatusUnauthorized,
		},
		{
			name: "duplicate JSON key", request: requestWithToken(http.MethodPost, "http://latch.local/v1", `{"safe":true,"safe":false}`, "application/json"),
			status: http.StatusBadRequest,
		},
		{
			name: "compressed body", request: requestWithToken(http.MethodPost, "http://latch.local/v1", "opaque", "application/json"),
			status: http.StatusUnsupportedMediaType,
		},
		{
			name: "encoded separator", request: requestWithToken(http.MethodGet, "http://latch.local/v1%2Fadmin", "", ""),
			status: http.StatusBadRequest,
		},
		{
			name: "nested encoded separator", request: requestWithToken(http.MethodGet, "http://latch.local/v1%252Fadmin", "", ""),
			status: http.StatusBadRequest,
		},
		{
			name: "duplicate semantic header", request: requestWithDuplicateHeader(),
			status: http.StatusRequestHeaderFieldsTooLarge,
		},
		{
			name: "trace", request: requestWithToken(http.MethodTrace, "http://latch.local/v1", "", ""),
			status: http.StatusMethodNotAllowed,
		},
	}
	tests[2].request.Header.Set("Content-Encoding", "gzip")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			handler := testHandler(t, service, func(*http.Request) (*http.Response, error) {
				calls++
				return response(http.StatusOK, `{}`, nil), nil
			})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, test.request)
			if recorder.Code != test.status || calls != 0 {
				t.Fatalf("status = %d, calls = %d, body = %s", recorder.Code, calls, recorder.Body.String())
			}
		})
	}
}

func TestHandlerDoesNotFollowOrExposeUpstreamRedirect(t *testing.T) {
	service := testService(t, &memoryLogger{})
	handler := testHandler(t, service, func(*http.Request) (*http.Response, error) {
		return response(http.StatusFound, "redirect", http.Header{"Location": {"https://evil.example/"}}), nil
	})
	request := requestWithToken(http.MethodGet, "http://latch.local/v1", "", "")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway || recorder.Header().Get("Location") != "" {
		t.Fatalf("status = %d, headers = %#v", recorder.Code, recorder.Header())
	}
}

func TestHandlerRedactsSecretQueryFromAudit(t *testing.T) {
	logger := &memoryLogger{}
	service := testService(t, logger)
	handler := testHandler(t, service, func(*http.Request) (*http.Response, error) {
		t.Fatal("hard-denied request reached upstream")
		return nil, nil
	})
	request := requestWithToken(http.MethodGet, "http://latch.local/export?api_key=top-secret", "", "")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(logger.events) != 1 {
		t.Fatalf("status = %d, events = %#v", recorder.Code, logger.events)
	}
	encoded, _ := json.Marshal(logger.events[0])
	if bytes.Contains(encoded, []byte("top-secret")) {
		t.Fatalf("audit event leaked query secret: %s", encoded)
	}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	service := testService(t, &memoryLogger{})
	for _, options := range []Options{
		{Service: service, UpstreamURL: "https://user:pass@example.test"},
		{Service: service, UpstreamURL: "https://example.test/../admin"},
		{Service: service, UpstreamURL: "https://example.test", GatewayToken: "short"},
		{Service: service, UpstreamURL: "https://example.test", UpstreamHeaders: http.Header{"Content-Type": {"text/plain"}}},
	} {
		if _, err := New(options); err == nil {
			t.Fatalf("New(%#v) succeeded, want error", options)
		}
	}
}

func requestWithToken(method, target, body, contentType string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("X-Latch-Token", testGatewayToken)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	return request
}

func requestWithDuplicateHeader() *http.Request {
	request := requestWithToken(http.MethodPost, "http://latch.local/v1", `{}`, "application/json")
	request.Header.Add("Content-Type", "text/plain")
	return request
}

func testHandler(t *testing.T, service *decision.Service, roundTrip func(*http.Request) (*http.Response, error)) *Handler {
	t.Helper()
	handler, err := New(Options{
		Service: service, AgentID: "api-agent", UpstreamURL: "https://api.example.test",
		GatewayToken: testGatewayToken, HTTPClient: &http.Client{Transport: roundTripFunc(roundTrip)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func testService(t *testing.T, logger audit.Logger, rules ...policy.Rule) *decision.Service {
	t.Helper()
	config := testPolicy(t)
	config.Rules = rules
	service, err := decision.New(config, logger, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testPolicy(t *testing.T) policy.Config {
	t.Helper()
	config := policy.DefaultConfig()
	state := t.TempDir()
	config.Audit.Path = filepath.Join(state, "audit.jsonl")
	config.Audit.Terminal = false
	config.Approvals.StorePath = filepath.Join(state, "approvals.json")
	config.Budgets.StorePath = filepath.Join(state, "budgets.json")
	config.Identity.RequireVerified = true
	config.Identity.Agents = []policy.AgentIdentity{{ID: "api-agent"}}
	return config
}

func response(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
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

package mcphttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/mcpadapter"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

func TestStreamableHTTPForwardsAllowAndHandlesDenialLocally(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get("MCP-Protocol-Version") != "2025-11-25" {
			t.Errorf("protocol version = %q", request.Header.Get("MCP-Protocol-Version"))
		}
		var input map[string]any
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		writeJSON(response, http.StatusOK, map[string]any{
			"jsonrpc": "2.0", "id": input["id"],
			"result": map[string]any{"content": []map[string]string{{"type": "text", "text": "upstream executed"}}},
		})
	}))
	defer upstream.Close()
	handler, logger := testHandler(t, upstream.URL, Options{AgentID: "desktop-agent"}, false)

	allowed := postMCP(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}`, nil)
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), "upstream executed") {
		t.Fatalf("allow status = %d, body = %s", allowed.Code, allowed.Body.String())
	}
	blocked := postMCP(t, handler, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"~/.ssh/id_rsa"}}}`, nil)
	if blocked.Code != http.StatusOK || !strings.Contains(blocked.Body.String(), `"isError":true`) || !strings.Contains(blocked.Body.String(), `"decision":"BLOCK"`) {
		t.Fatalf("block status = %d, body = %s", blocked.Code, blocked.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
	events := logger.snapshot()
	if len(events) != 2 || events[0].Action.Metadata["transport"] != "streamable-http" || !events[0].Assessment.IdentityVerified {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestStreamableHTTPSessionCarriesUntrustedInitializeIdentity(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var input map[string]any
		_ = json.NewDecoder(request.Body).Decode(&input)
		if input["method"] == "initialize" {
			response.Header().Set("MCP-Session-Id", "session-123")
		}
		writeJSON(response, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": input["id"], "result": map[string]any{}})
	}))
	defer upstream.Close()
	handler, logger := testHandler(t, upstream.URL, Options{}, false)

	initialized := postMCP(t, handler, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"desktop-client","version":"1"}}}`, nil)
	if initialized.Header().Get("MCP-Session-Id") != "session-123" {
		t.Fatalf("session header = %q", initialized.Header().Get("MCP-Session-Id"))
	}
	called := postMCP(t, handler, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}`, map[string]string{"MCP-Session-Id": "session-123"})
	if called.Code != http.StatusOK {
		t.Fatalf("call status = %d, body = %s", called.Code, called.Body.String())
	}
	events := logger.snapshot()
	if len(events) != 1 || events[0].Action.AgentID != "desktop-client" || events[0].Assessment.IdentitySource != "mcp_initialize" || events[0].Assessment.IdentityVerified {
		t.Fatalf("identity event = %#v", events)
	}
}

func TestStreamableHTTPAuthenticationOriginAndCredentialBoundary(t *testing.T) {
	var upstreamAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamAuthorization = request.Header.Get("Authorization")
		response.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	handler, _ := testHandler(t, upstream.URL, Options{
		BearerToken: "proxy-token-with-at-least-32-bytes!", UpstreamBearerToken: "upstream-secret",
		AllowedOrigins: []string{"https://client.example"},
	}, false)

	unauthorized := postMCP(t, handler, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
	forbidden := postMCP(t, handler, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{
		"Authorization": "Bearer proxy-token-with-at-least-32-bytes!", "Origin": "https://evil.example",
	})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("forbidden status = %d", forbidden.Code)
	}
	allowed := postMCP(t, handler, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{
		"Authorization": "Bearer proxy-token-with-at-least-32-bytes!", "Origin": "https://client.example",
	})
	if allowed.Code != http.StatusAccepted || allowed.Header().Get("Access-Control-Allow-Origin") != "https://client.example" {
		t.Fatalf("allowed status = %d, headers = %#v", allowed.Code, allowed.Header())
	}
	if upstreamAuthorization != "Bearer upstream-secret" {
		t.Fatalf("upstream authorization = %q", upstreamAuthorization)
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	preflight.Header.Set("Origin", "https://client.example")
	preflightResponse := httptest.NewRecorder()
	handler.ServeHTTP(preflightResponse, preflight)
	if preflightResponse.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d", preflightResponse.Code)
	}
}

func TestStreamableHTTPRejectsMalformedOversizedAndNonConformingRequests(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		response.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	handler, _ := testHandler(t, upstream.URL, Options{MaxBodyBytes: 1024}, false)

	cases := []struct {
		name   string
		body   string
		mutate func(*http.Request)
		status int
	}{
		{name: "invalid JSON", body: `{`, status: http.StatusBadRequest},
		{name: "batch", body: `[{"jsonrpc":"2.0","method":"ping"}]`, status: http.StatusBadRequest},
		{name: "duplicate method", body: `{"jsonrpc":"2.0","method":"tools/call","method":"ping","params":{"name":"filesystem.read"}}`, status: http.StatusBadRequest},
		{name: "duplicate argument", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"~/.ssh/id_rsa","path":"./README.md"}}}`, status: http.StatusBadRequest},
		{name: "oversized", body: `{"jsonrpc":"2.0","method":"ping","padding":"` + strings.Repeat("x", 2048) + `"}`, status: http.StatusRequestEntityTooLarge},
		{name: "content type", body: `{"jsonrpc":"2.0","method":"ping"}`, mutate: func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") }, status: http.StatusUnsupportedMediaType},
		{name: "accept", body: `{"jsonrpc":"2.0","method":"ping"}`, mutate: func(request *http.Request) { request.Header.Set("Accept", "application/json") }, status: http.StatusNotAcceptable},
		{name: "session", body: `{"jsonrpc":"2.0","method":"ping"}`, mutate: func(request *http.Request) { request.Header.Set("MCP-Session-Id", "bad session") }, status: http.StatusBadRequest},
		{name: "query", body: `{"jsonrpc":"2.0","method":"ping"}`, mutate: func(request *http.Request) { request.URL.RawQuery = "session=smuggled" }, status: http.StatusBadRequest},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := newMCPRequest(test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid requests reached upstream: %d", calls.Load())
	}
}

func TestStreamableHTTPFailsClosedOnAuditFailureRedirectAndInvalidUpstreamSession(t *testing.T) {
	t.Run("audit", func(t *testing.T) {
		var calls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			response.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()
		handler, _ := testHandler(t, upstream.URL, Options{AgentID: "desktop-agent"}, true)
		response := postMCP(t, handler, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}`, nil)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"decision_source":"audit_failure"`) || calls.Load() != 0 {
			t.Fatalf("status = %d, calls = %d, body = %s", response.Code, calls.Load(), response.Body.String())
		}
	})

	for name, upstreamHandler := range map[string]http.HandlerFunc{
		"redirect": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Location", "https://example.invalid/mcp")
			response.WriteHeader(http.StatusTemporaryRedirect)
		},
		"invalid session": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("MCP-Session-Id", "bad session")
			writeJSON(response, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(upstreamHandler)
			defer upstream.Close()
			handler, _ := testHandler(t, upstream.URL, Options{}, false)
			response := postMCP(t, handler, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, nil)
			if response.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestStreamableHTTPPassesThroughSSEAndDeletesSessions(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPost:
			response.Header().Set("MCP-Session-Id", "stream-session")
			writeJSON(response, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}})
		case http.MethodGet:
			response.Header().Set("Content-Type", "text/event-stream")
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n"))
		case http.MethodDelete:
			response.WriteHeader(http.StatusNoContent)
		}
	}))
	defer upstream.Close()
	handler, _ := testHandler(t, upstream.URL, Options{}, false)
	postMCP(t, handler, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, nil)
	if _, exists := handler.sessions.get("stream-session"); !exists {
		t.Fatal("initialized session was not retained")
	}

	get := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	get.Header.Set("Accept", "text/event-stream")
	get.Header.Set("MCP-Session-Id", "stream-session")
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(getResponse.Body.String(), "notifications/tools/list_changed") {
		t.Fatalf("GET status = %d, headers = %#v, body = %s", getResponse.Code, getResponse.Header(), getResponse.Body.String())
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	deleteRequest.Header.Set("MCP-Session-Id", "stream-session")
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d", deleteResponse.Code)
	}
	if _, exists := handler.sessions.get("stream-session"); exists {
		t.Fatal("terminated session remained cached")
	}
}

func TestStreamableHTTPConfigurationRejectsWeakSecurityInputs(t *testing.T) {
	config := httpTestConfig(t)
	service, err := decision.New(config, &memoryLogger{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, options := range map[string]Options{
		"weak token":      {Service: service, UpstreamURL: "https://example.test/mcp", BearerToken: "weak"},
		"credential URL":  {Service: service, UpstreamURL: "https://user@example.test/mcp"},
		"wildcard origin": {Service: service, UpstreamURL: "https://example.test/mcp", AllowedOrigins: []string{"*"}},
		"bad endpoint":    {Service: service, UpstreamURL: "https://example.test/mcp", EndpointPath: "mcp"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(options); err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
		})
	}
}

func testHandler(t *testing.T, upstream string, options Options, failAudit bool) (*Handler, *memoryLogger) {
	t.Helper()
	logger := &memoryLogger{}
	var auditLogger audit.Logger = logger
	if failAudit {
		auditLogger = failingLogger{}
	}
	service, err := decision.New(httpTestConfig(t), auditLogger, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options.Service = service
	options.UpstreamURL = upstream
	handler, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return handler, logger
}

func httpTestConfig(t *testing.T) policy.Config {
	t.Helper()
	config := policy.DefaultConfig()
	state := t.TempDir()
	config.Audit.Path = filepath.Join(state, "audit.jsonl")
	config.Audit.Terminal = false
	config.Approvals.StorePath = filepath.Join(state, "approvals.json")
	config.Budgets.StorePath = filepath.Join(state, "budgets.json")
	config.Identity.Agents = []policy.AgentIdentity{{ID: "desktop-agent"}}
	config.Rules = []policy.Rule{{
		ID: "block-private-keys", Match: policy.Match{Path: policy.StringList{"~/.ssh/**"}}, Action: models.DecisionBlock,
	}}
	return config
}

func newMCPRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-11-25")
	return request
}

func postMCP(t *testing.T, handler http.Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := newMCPRequest(body)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, _ := json.Marshal(value)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

type memoryLogger struct {
	mu     sync.Mutex
	events []models.AuditEvent
}

func (logger *memoryLogger) Write(event models.AuditEvent) error {
	logger.mu.Lock()
	defer logger.mu.Unlock()
	logger.events = append(logger.events, event)
	return nil
}

func (logger *memoryLogger) snapshot() []models.AuditEvent {
	logger.mu.Lock()
	defer logger.mu.Unlock()
	return append([]models.AuditEvent(nil), logger.events...)
}

type failingLogger struct{}

func (failingLogger) Write(models.AuditEvent) error { return fmt.Errorf("audit unavailable") }

func TestSessionCacheExpiresAndEvictsOldest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newSessionCache(2, time.Minute, func() time.Time { return now })
	cache.put("one", nil)
	now = now.Add(time.Second)
	cache.put("two", nil)
	now = now.Add(time.Second)
	cache.put("three", nil)
	if _, exists := cache.get("one"); exists {
		t.Fatal("oldest session was not evicted")
	}
	now = now.Add(2 * time.Minute)
	if _, exists := cache.get("three"); exists {
		t.Fatal("expired session was not pruned")
	}
}

func TestSessionCacheRejectsIdentityCollision(t *testing.T) {
	cache := newSessionCache(2, time.Minute, time.Now)
	first := mcpadapter.NewSession("first")
	second := mcpadapter.NewSession("second")
	if !cache.put("shared", first) || cache.put("shared", second) {
		t.Fatal("session identity collision was accepted")
	}
	stored, exists := cache.get("shared")
	if !exists || stored != first {
		t.Fatal("collision replaced the original session")
	}
}

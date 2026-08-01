package mcpstdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/princebabou/Latch/internal/approval"
	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

func TestWriteMessageAvoidsSizeArithmeticAndHandlesPartialWrites(t *testing.T) {
	writer := &chunkWriter{max: 2}
	if err := writeMessage(writer, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := writer.buffer.String(); got != "hello\n" {
		t.Fatalf("output = %q, want %q", got, "hello\n")
	}
}

func TestWriteMessageFailsOnWriterWithoutProgress(t *testing.T) {
	err := writeMessage(zeroWriter{}, []byte("message"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want io.ErrShortWrite", err)
	}
}

func TestProxyForwardsAllowedToolCallAndSessionTraffic(t *testing.T) {
	logger := &memoryLogger{}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"integration-client","version":"1.0.0"}}}`,
		`{"jsonrpc":"2.0","id":"server-question","result":{"accepted":true}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}`,
	}, "\n") + "\n"

	output, runErr := runHelperProxy(t, input, logger, "")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	if len(messages) != 4 {
		t.Fatalf("received %d server messages, want 4: %s", len(messages), output)
	}
	if got := nestedString(messages[3], "result", "content", "0", "text"); !strings.Contains(got, "executed filesystem.read") {
		t.Fatalf("tool result = %q, expected upstream execution result", got)
	}
	events := logger.snapshot()
	if len(events) != 1 {
		t.Fatalf("audited %d actions, want 1", len(events))
	}
	if events[0].Action.AgentID != "integration-client" {
		t.Fatalf("agent id = %q, want discovered initialize identity", events[0].Action.AgentID)
	}
	if events[0].Assessment.Decision != models.DecisionAllow {
		t.Fatalf("decision = %s, want ALLOW", events[0].Assessment.Decision)
	}
}

func TestProxyBlocksSensitiveToolCallBeforeExecution(t *testing.T) {
	logger := &memoryLogger{}
	input := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"~/.ssh/id_rsa"}}}` + "\n"
	output, runErr := runHelperProxy(t, input, logger, "")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	if len(messages) != 1 {
		t.Fatalf("received %d messages, want one local denial: %s", len(messages), output)
	}
	if got := nestedBool(messages[0], "result", "isError"); !got {
		t.Fatal("blocked tool response did not set isError")
	}
	if got := nestedString(messages[0], "result", "_meta", "io.latch/security", "decision"); got != "BLOCK" {
		t.Fatalf("decision metadata = %q, want BLOCK", got)
	}
	if got := nestedString(messages[0], "result", "_meta", "io.latch/security", "decision_source"); got != "policy_block" {
		t.Fatalf("decision source = %q, want policy_block", got)
	}
	if text := nestedString(messages[0], "result", "content", "0", "text"); strings.Contains(text, "id_rsa") {
		t.Fatalf("denial leaked resource details: %q", text)
	}
	events := logger.snapshot()
	if len(events) != 1 || events[0].Assessment.Decision != models.DecisionBlock {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestProxyReturnsPendingApprovalWithoutExecution(t *testing.T) {
	logger := &memoryLogger{}
	input := `{"jsonrpc":"2.0","id":"approval","method":"tools/call","params":{"name":"shell.exec","arguments":{"command":"npm test"}}}` + "\n"
	output, runErr := runHelperProxy(t, input, logger, "")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	if got := nestedString(messages[0], "result", "_meta", "io.latch/security", "decision"); got != "REQUIRE_APPROVAL" {
		t.Fatalf("decision metadata = %q, want REQUIRE_APPROVAL", got)
	}
	if got := nestedString(messages[0], "result", "_meta", "io.latch/security", "decision_source"); got != "policy_approval" {
		t.Fatalf("decision source = %q, want policy_approval", got)
	}
	if events := logger.snapshot(); len(events) != 1 || events[0].Approval != "pending" {
		t.Fatalf("approval audit = %#v", events)
	}
}

func TestProxyRejectsMalformedToolCallAsProtocolError(t *testing.T) {
	logger := &memoryLogger{}
	input := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"filesystem.read","arguments":"not-an-object"}}` + "\n"
	output, runErr := runHelperProxy(t, input, logger, "")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	if got := nestedNumber(messages[0], "error", "code"); got != -32602 {
		t.Fatalf("error code = %v, want -32602", got)
	}
	if len(logger.snapshot()) != 0 {
		t.Fatal("malformed call should not create an action audit event")
	}
}

func TestProxyRejectsDuplicateJSONKeysBeforeForwarding(t *testing.T) {
	logger := &memoryLogger{}
	input := `{"jsonrpc":"2.0","id":9,"method":"tools/call","method":"ping","params":{"name":"filesystem.read","arguments":{"path":"~/.ssh/id_rsa","path":"./README.md"}}}` + "\n"
	output, runErr := runHelperProxy(t, input, logger, "")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	if len(messages) != 1 || nestedNumber(messages[0], "error", "code") != -32700 {
		t.Fatalf("output = %s", output)
	}
	if len(logger.snapshot()) != 0 {
		t.Fatal("ambiguous JSON should not create an audit event")
	}
}

func TestProxyFailsClosedOnInvalidUpstreamStdout(t *testing.T) {
	logger := &memoryLogger{}
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}` + "\n"
	output, runErr := runHelperProxy(t, input, logger, "invalid")
	if runErr == nil || !strings.Contains(runErr.Error(), "invalid JSON-RPC") {
		t.Fatalf("error = %v, want invalid upstream protocol error", runErr)
	}
	messages := decodeOutput(t, output)
	if got := nestedNumber(messages[0], "error", "code"); got != -32603 {
		t.Fatalf("error code = %v, want -32603", got)
	}
}

func TestProxyFailsClosedWhenAuditCannotBeWritten(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}` + "\n"
	output, runErr := runHelperProxy(t, input, failingLogger{}, "")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	if got := nestedString(messages[0], "result", "_meta", "io.latch/security", "decision"); got != "BLOCK" {
		t.Fatalf("decision metadata = %q, want BLOCK", got)
	}
	if got := nestedString(messages[0], "result", "_meta", "io.latch/security", "decision_source"); got != "audit_failure" {
		t.Fatalf("decision source = %q, want audit_failure", got)
	}
	if text := nestedString(messages[0], "result", "content", "0", "text"); !strings.Contains(text, "safely audit") {
		t.Fatalf("tool error = %q, want audit failure message", text)
	}
}

func TestProxyRejectsSelfAssertedIdentityWhenVerificationIsRequired(t *testing.T) {
	logger := &memoryLogger{}
	config := proxyTestConfig(t)
	config.Identity.RequireVerified = true
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"spoofed-admin","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}`,
	}, "\n") + "\n"
	output, runErr := runHelperProxyWithConfig(t, input, logger, "", config, "")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	var denial map[string]any
	for _, message := range messages {
		if nestedString(message, "result", "_meta", "io.latch/security", "decision_source") != "" {
			denial = message
			break
		}
	}
	if denial == nil {
		t.Fatalf("missing local identity denial: %s", output)
	}
	if got := nestedString(denial, "result", "_meta", "io.latch/security", "decision_source"); got != "identity_unverified" {
		t.Fatalf("decision source = %q, want identity_unverified; output=%s", got, output)
	}
	if got := nestedBool(denial, "result", "_meta", "io.latch/security", "identity_verified"); got {
		t.Fatal("self-asserted MCP identity was marked verified")
	}
	events := logger.snapshot()
	if len(events) != 1 || events[0].Assessment.IdentitySource != "mcp_initialize" {
		t.Fatalf("events = %#v", events)
	}
}

func TestProxyConfiguredIdentityUsesCapabilityCeiling(t *testing.T) {
	config := proxyTestConfig(t)
	config.Identity = policy.IdentityConfig{
		RequireVerified: true, EnforceCapabilities: true,
		Agents: []policy.AgentIdentity{{
			ID: "desktop-agent",
			Capabilities: []policy.Capability{{
				ID: "workspace-read",
				Match: policy.Match{
					Tool: policy.StringList{"filesystem.read"},
					Path: policy.StringList{"./**"},
				},
			}},
		}},
	}

	t.Run("allowed capability", func(t *testing.T) {
		logger := &memoryLogger{}
		input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}` + "\n"
		output, runErr := runHelperProxyWithConfig(t, input, logger, "", config, "desktop-agent")
		if runErr != nil {
			t.Fatal(runErr)
		}
		messages := decodeOutput(t, output)
		if text := nestedString(messages[0], "result", "content", "0", "text"); !strings.Contains(text, "executed filesystem.read") {
			t.Fatalf("output = %s", output)
		}
		events := logger.snapshot()
		if len(events) != 1 || !events[0].Assessment.IdentityVerified {
			t.Fatalf("events = %#v", events)
		}
		if capabilities := events[0].Assessment.MatchedCapabilities; len(capabilities) != 1 || capabilities[0] != "workspace-read" {
			t.Fatalf("capabilities = %#v", capabilities)
		}
	})

	t.Run("denied outside capability", func(t *testing.T) {
		logger := &memoryLogger{}
		input := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell.exec","arguments":{"command":"npm test"}}}` + "\n"
		output, runErr := runHelperProxyWithConfig(t, input, logger, "", config, "desktop-agent")
		if runErr != nil {
			t.Fatal(runErr)
		}
		messages := decodeOutput(t, output)
		if got := nestedString(messages[0], "result", "_meta", "io.latch/security", "decision_source"); got != "capability_denied" {
			t.Fatalf("decision source = %q, want capability_denied", got)
		}
		if events := logger.snapshot(); len(events) != 1 || events[0].Approval != "" {
			t.Fatalf("capability denial reached approval path: %#v", events)
		}
	})
}

func TestProxyAtomicallyBlocksCallsAfterAgentBudgetIsExhausted(t *testing.T) {
	logger := &memoryLogger{}
	config := proxyTestConfig(t)
	config.Identity.RequireVerified = true
	config.Identity.Agents = []policy.AgentIdentity{{ID: "desktop-agent"}}
	config.Budgets.StorePath = t.TempDir() + string(os.PathSeparator) + "budgets.json"
	config.Budgets.Rules = []policy.BudgetRule{{
		ID: "read-burst",
		Match: policy.Match{
			Tool: policy.StringList{"filesystem.read"},
		},
		MaxActions: 1,
		Window:     policy.Duration(time.Minute),
	}}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}`,
	}, "\n") + "\n"

	output, runErr := runHelperProxyWithConfig(t, input, logger, "", config, "desktop-agent")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	var upstreamExecutions, budgetDenials int
	for _, message := range messages {
		if text := nestedString(message, "result", "content", "0", "text"); strings.Contains(text, "executed filesystem.read") {
			upstreamExecutions++
		}
		if source := nestedString(message, "result", "_meta", "io.latch/security", "decision_source"); source == "budget_exhausted" {
			budgetDenials++
		}
	}
	if upstreamExecutions != 1 || budgetDenials != 1 {
		t.Fatalf("upstream executions = %d, budget denials = %d, output = %s", upstreamExecutions, budgetDenials, output)
	}
	events := logger.snapshot()
	if len(events) != 2 {
		t.Fatalf("audit events = %#v", events)
	}
	if events[0].Assessment.Decision != models.DecisionAllow ||
		len(events[0].Assessment.Budgets) != 1 ||
		events[0].Assessment.Budgets[0].Used != 1 ||
		events[0].Assessment.Budgets[0].Exceeded {
		t.Fatalf("first event = %#v", events[0])
	}
	if events[1].Assessment.DecisionSource != "budget_exhausted" {
		t.Fatalf("second event = %#v", events[1])
	}
}

func TestProxyFailsClosedWhenBudgetStateIsCorrupt(t *testing.T) {
	logger := &memoryLogger{}
	config := proxyTestConfig(t)
	config.Identity.RequireVerified = true
	config.Identity.Agents = []policy.AgentIdentity{{ID: "desktop-agent"}}
	config.Budgets.StorePath = t.TempDir() + string(os.PathSeparator) + "budgets.json"
	config.Budgets.Rules = []policy.BudgetRule{{
		ID: "read-burst",
		Match: policy.Match{
			Tool: policy.StringList{"filesystem.read"},
		},
		MaxActions: 1,
		Window:     policy.Duration(time.Minute),
	}}
	if err := os.WriteFile(config.Budgets.StorePath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"./README.md"}}}` + "\n"

	output, runErr := runHelperProxyWithConfig(t, input, logger, "", config, "desktop-agent")
	if runErr != nil {
		t.Fatal(runErr)
	}
	messages := decodeOutput(t, output)
	if len(messages) != 1 {
		t.Fatalf("messages = %#v", messages)
	}
	if source := nestedString(messages[0], "result", "_meta", "io.latch/security", "decision_source"); source != "budget_store_failure" {
		t.Fatalf("decision source = %q, output = %s", source, output)
	}
	events := logger.snapshot()
	if len(events) != 1 || events[0].Assessment.DecisionSource != "budget_store_failure" {
		t.Fatalf("audit events = %#v", events)
	}
}

func runHelperProxy(t *testing.T, input string, logger audit.Logger, mode string) (string, error) {
	t.Helper()
	return runHelperProxyWithConfig(t, input, logger, mode, proxyTestConfig(t), "")
}

func proxyTestConfig(t *testing.T) policy.Config {
	t.Helper()
	config := policy.DefaultConfig()
	config.Audit.Terminal = false
	config.Audit.Path = t.TempDir() + string(os.PathSeparator) + "audit.jsonl"
	config.Rules = []policy.Rule{
		{ID: "block-private-keys", Description: "Private keys are prohibited.", Match: policy.Match{Path: policy.StringList{"~/.ssh/**", "**/*.key"}}, Action: models.DecisionBlock},
		{ID: "approve-shell", Description: "Shell calls need approval.", Match: policy.Match{Tool: policy.StringList{"shell.exec"}}, Action: models.DecisionRequireApproval},
	}
	return config
}

func runHelperProxyWithConfig(t *testing.T, input string, logger audit.Logger, mode string, config policy.Config, agentID string) (string, error) {
	t.Helper()
	store, err := approval.NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	store.Path = t.TempDir() + string(os.PathSeparator) + "approvals.json"
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = Run(ctx, Options{
		Policy:          config,
		AgentID:         agentID,
		Command:         os.Args[0],
		Arguments:       []string{"-test.run=^TestMCPHelperProcess$"},
		Environment:     []string{"LATCH_MCP_HELPER=1", "LATCH_MCP_HELPER_MODE=" + mode},
		Input:           strings.NewReader(input),
		Output:          &output,
		ErrorOutput:     &diagnostics,
		AuditLogger:     logger,
		ApprovalStore:   &store,
		ShutdownTimeout: 2 * time.Second,
	})
	return output.String(), err
}

// TestMCPHelperProcess runs as a child process of the integration tests. It is
// a minimal MCP server that proves the proxy is enforcing before forwarding.
func TestMCPHelperProcess(t *testing.T) {
	if os.Getenv("LATCH_MCP_HELPER") != "1" {
		return
	}
	reader := bufio.NewScanner(os.Stdin)
	writer := json.NewEncoder(os.Stdout)
	for reader.Scan() {
		if os.Getenv("LATCH_MCP_HELPER_MODE") == "invalid" {
			fmt.Fprintln(os.Stdout, "upstream debug log accidentally written to stdout")
			os.Exit(0)
		}
		var message map[string]any
		if json.Unmarshal(reader.Bytes(), &message) != nil {
			os.Exit(2)
		}
		method, _ := message["method"].(string)
		switch method {
		case "initialize":
			_ = writer.Encode(map[string]any{"jsonrpc": "2.0", "id": message["id"], "result": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "test-server", "version": "1.0.0"}}})
			_ = writer.Encode(map[string]any{"jsonrpc": "2.0", "id": "server-question", "method": "roots/list", "params": map[string]any{}})
		case "tools/call":
			params, _ := message["params"].(map[string]any)
			name, _ := params["name"].(string)
			_ = writer.Encode(map[string]any{"jsonrpc": "2.0", "id": message["id"], "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "executed " + name}}}})
		case "":
			_ = writer.Encode(map[string]any{"jsonrpc": "2.0", "method": "test/response_received", "params": map[string]any{}})
		}
	}
	os.Exit(0)
}

type memoryLogger struct {
	mu     sync.Mutex
	events []models.AuditEvent
}

type failingLogger struct{}

func (failingLogger) Write(models.AuditEvent) error { return fmt.Errorf("test audit failure") }

type chunkWriter struct {
	buffer bytes.Buffer
	max    int
}

func (writer *chunkWriter) Write(payload []byte) (int, error) {
	if len(payload) > writer.max {
		payload = payload[:writer.max]
	}
	return writer.buffer.Write(payload)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func (l *memoryLogger) Write(event models.AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	return nil
}

func (l *memoryLogger) snapshot() []models.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]models.AuditEvent(nil), l.events...)
}

func decodeOutput(t *testing.T, output string) []map[string]any {
	t.Helper()
	var messages []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var message map[string]any
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			t.Fatalf("invalid JSON-RPC output %q: %v", line, err)
		}
		messages = append(messages, message)
	}
	return messages
}

func nestedString(value any, path ...string) string {
	current := value
	for _, part := range path {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[part]
		case []any:
			if part == "0" && len(typed) > 0 {
				current = typed[0]
			} else {
				return ""
			}
		default:
			return ""
		}
	}
	result, _ := current.(string)
	return result
}

func nestedBool(value any, path ...string) bool {
	current := nestedValue(value, path...)
	result, _ := current.(bool)
	return result
}

func nestedNumber(value any, path ...string) float64 {
	current := nestedValue(value, path...)
	result, _ := current.(float64)
	return result
}

func nestedValue(value any, path ...string) any {
	current := value
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

// Package mcpstdio implements a policy-enforcing MCP stdio transport proxy.
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
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/princebabou/Latch/internal/approval"
	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/budget"
	"github.com/princebabou/Latch/internal/enforce"
	"github.com/princebabou/Latch/internal/normalize"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	defaultMaxMessageBytes = 4 << 20
	defaultShutdownTimeout = 5 * time.Second
)

var errMessageTooLarge = errors.New("MCP message exceeds configured size limit")

// Options describes one stdio proxy process. The proxy owns the child server's
// lifetime and reserves Output exclusively for newline-delimited JSON-RPC.
type Options struct {
	Policy          policy.Config
	AgentID         string
	Command         string
	Arguments       []string
	Directory       string
	Environment     []string
	MaxMessageBytes int
	ShutdownTimeout time.Duration
	Input           io.Reader
	Output          io.Writer
	ErrorOutput     io.Writer
	AuditLogger     audit.Logger
	ApprovalStore   *approval.Store
	BudgetStore     *budget.Store
}

// Run starts the upstream MCP server, transparently forwards its entire MCP
// session, and intercepts tools/call before it reaches the server.
func Run(ctx context.Context, options Options) error {
	if strings.TrimSpace(options.Command) == "" {
		return fmt.Errorf("upstream MCP server command is required")
	}
	if err := options.applyDefaults(); err != nil {
		return err
	}

	protocolOut := &lockedWriter{writer: options.Output}
	diagnosticOut := &lockedWriter{writer: options.ErrorOutput}
	command := exec.CommandContext(ctx, options.Command, options.Arguments...)
	command.Dir = options.Directory
	if len(options.Environment) > 0 {
		command.Env = append(os.Environ(), options.Environment...)
	}
	serverInput, err := command.StdinPipe()
	if err != nil {
		return fmt.Errorf("open upstream stdin: %w", err)
	}
	serverOutput, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open upstream stdout: %w", err)
	}
	command.Stderr = diagnosticOut
	if err := command.Start(); err != nil {
		return fmt.Errorf("start upstream MCP server: %w", err)
	}

	session := &sessionIdentity{configured: strings.TrimSpace(options.AgentID)}
	clientDone := make(chan error, 1)
	serverDone := make(chan error, 1)
	waitDone := make(chan error, 1)

	go func() {
		clientDone <- pumpClient(options, session, options.Input, serverInput, protocolOut, diagnosticOut)
	}()
	go func() {
		serverDone <- pumpServer(serverOutput, protocolOut, options.MaxMessageBytes)
	}()
	go func() { waitDone <- command.Wait() }()

	var firstErr error
	serverFinished, processFinished := false, false
	select {
	case err := <-clientDone:
		firstErr = err
		_ = serverInput.Close()
		if err != nil {
			_ = command.Process.Kill()
		}
	case err := <-serverDone:
		serverFinished = true
		firstErr = err
		_ = serverInput.Close()
		if err != nil {
			_ = command.Process.Kill()
		}
	case err := <-waitDone:
		processFinished = true
		firstErr = normalizeProcessError(err)
		_ = serverInput.Close()
	case <-ctx.Done():
		firstErr = ctx.Err()
		_ = serverInput.Close()
		_ = command.Process.Kill()
	}

	deadline := time.NewTimer(options.ShutdownTimeout)
	defer deadline.Stop()
	for !serverFinished || !processFinished {
		select {
		case err := <-serverDone:
			serverFinished = true
			if firstErr == nil {
				firstErr = err
			}
		case err := <-waitDone:
			processFinished = true
			if firstErr == nil {
				firstErr = normalizeProcessError(err)
			}
		case <-deadline.C:
			_ = command.Process.Kill()
			if firstErr == nil {
				firstErr = fmt.Errorf("upstream MCP server did not shut down within %s", options.ShutdownTimeout)
			}
			deadline.Reset(options.ShutdownTimeout)
		case <-ctx.Done():
			_ = command.Process.Kill()
			if firstErr == nil {
				firstErr = ctx.Err()
			}
		}
	}
	return firstErr
}

func (options *Options) applyDefaults() error {
	if options.MaxMessageBytes <= 0 {
		options.MaxMessageBytes = defaultMaxMessageBytes
	}
	if options.ShutdownTimeout <= 0 {
		options.ShutdownTimeout = defaultShutdownTimeout
	}
	if options.Input == nil {
		options.Input = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if options.ErrorOutput == nil {
		options.ErrorOutput = os.Stderr
	}
	if options.AuditLogger == nil {
		options.AuditLogger = audit.JSONLLogger{Path: options.Policy.Audit.Path}
	}
	if options.ApprovalStore == nil {
		store, err := approval.NewStore(options.Policy)
		if err != nil {
			return fmt.Errorf("configure approval store: %w", err)
		}
		options.ApprovalStore = &store
	}
	if options.BudgetStore == nil {
		store, err := budget.NewStore(options.Policy)
		if err != nil {
			return fmt.Errorf("configure action budgets: %w", err)
		}
		options.BudgetStore = &store
	}
	return nil
}

func pumpClient(options Options, session *sessionIdentity, input io.Reader, serverInput io.Writer, protocolOut, diagnosticOut *lockedWriter) error {
	reader := bufio.NewReaderSize(input, min(options.MaxMessageBytes, 64<<10))
	for {
		message, err := readMessage(reader, options.MaxMessageBytes)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read MCP client message: %w", err)
		}
		forward, err := inspectClientMessage(options, session, message, protocolOut, diagnosticOut)
		if err != nil {
			return err
		}
		if forward {
			if err := writeMessage(serverInput, message); err != nil {
				return fmt.Errorf("forward message to upstream MCP server: %w", err)
			}
		}
	}
}

func pumpServer(input io.Reader, output *lockedWriter, maxMessageBytes int) error {
	reader := bufio.NewReaderSize(input, min(maxMessageBytes, 64<<10))
	for {
		message, err := readMessage(reader, maxMessageBytes)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			_ = writeProtocolError(output, nil, -32603, "Latch: upstream MCP server produced an invalid message")
			return fmt.Errorf("read upstream MCP server message: %w", err)
		}
		if err := validateServerMessage(message); err != nil {
			_ = writeProtocolError(output, nil, -32603, "Latch: upstream MCP server produced invalid protocol data")
			return err
		}
		if err := writeMessage(output, message); err != nil {
			return fmt.Errorf("forward upstream MCP server message: %w", err)
		}
	}
}

func inspectClientMessage(options Options, session *sessionIdentity, message []byte, protocolOut, diagnosticOut *lockedWriter) (bool, error) {
	object, err := decodeObject(message)
	if err != nil {
		if writeErr := writeProtocolError(protocolOut, nil, -32700, "Latch: invalid JSON-RPC message"); writeErr != nil {
			return false, writeErr
		}
		return false, nil
	}
	if stringValue(object["jsonrpc"]) != "2.0" {
		id := validResponseID(object["id"])
		if writeErr := writeProtocolError(protocolOut, id, -32600, "Latch: invalid JSON-RPC request"); writeErr != nil {
			return false, writeErr
		}
		return false, nil
	}
	method := stringValue(object["method"])
	if method == "initialize" {
		session.observeInitialize(object["params"])
		return true, nil
	}
	if method != "tools/call" {
		return true, nil
	}

	id := validRequestID(object["id"])
	if id == nil {
		return false, writeProtocolError(protocolOut, nil, -32600, "Latch: tools/call requires a valid request id")
	}
	call, err := decodeToolCall(object["params"])
	if err != nil {
		return false, writeProtocolError(protocolOut, id, -32602, "Latch: invalid tools/call parameters")
	}
	session.observeRequestMeta(call.Meta)
	identity := session.identityContext()
	action, err := normalize.Action(normalize.Request{
		AgentID:   identity.ID,
		Tool:      call.Name,
		Arguments: call.Arguments,
		Metadata: map[string]any{
			"protocol":          "mcp",
			"transport":         "stdio",
			"method":            "tools/call",
			"identity_verified": identity.Verified,
			"identity_source":   identity.Source,
		},
	})
	if err != nil {
		return false, writeProtocolError(protocolOut, id, -32602, "Latch: invalid tools/call parameters")
	}

	action, identity = enforce.CanonicalizeIdentity(options.Policy, action, identity)
	assessment := enforce.EvaluateWithIdentity(options.Policy, action, identity)
	approvalStatus := ""
	if assessment.Decision != models.DecisionBlock {
		statuses, budgetErr := options.BudgetStore.Check(action)
		assessment = budget.Apply(assessment, statuses, budgetErr)
		if budgetErr != nil {
			fmt.Fprintln(diagnosticOut, "Latch: action budget store unavailable; action blocked")
		}
	}
	if assessment.Decision == models.DecisionRequireApproval {
		grant, allowed, approvalErr := options.ApprovalStore.IsAllowed(action)
		if approvalErr != nil {
			assessment.Decision = models.DecisionBlock
			assessment.DecisionSource = "approval_store_failure"
			assessment.Reasons = append(assessment.Reasons, "Approval state could not be read safely")
			approvalStatus = "store_error"
			fmt.Fprintln(diagnosticOut, "Latch: approval store unavailable; action blocked")
		} else if allowed {
			assessment.Decision = models.DecisionAllow
			assessment.DecisionSource = "approval_cache"
			assessment.Reasons = append(assessment.Reasons, fmt.Sprintf("Approved by %s until %s", grant.Approver, grant.ExpiresAt.Format(time.RFC3339)))
			approvalStatus = "grant:" + grant.ID
		} else {
			approvalStatus = "pending"
		}
	}
	if assessment.Decision == models.DecisionAllow {
		statuses, budgetErr := options.BudgetStore.Reserve(action)
		assessment = budget.Apply(assessment, statuses, budgetErr)
		if budgetErr != nil {
			fmt.Fprintln(diagnosticOut, "Latch: action budget reservation failed; action blocked")
		}
	}

	event := audit.NewEvent(action, assessment, approvalStatus)
	if err := options.AuditLogger.Write(event); err != nil {
		assessment.Decision = models.DecisionBlock
		assessment.DecisionSource = "audit_failure"
		assessment.Reasons = append(assessment.Reasons, "Required audit logging failed")
		fmt.Fprintln(diagnosticOut, "Latch: audit write failed; action blocked")
		return false, writeToolDecision(protocolOut, id, assessment, true)
	}
	if options.Policy.Audit.Terminal {
		fmt.Fprintln(diagnosticOut, audit.Terminal(event))
	}
	if assessment.Decision == models.DecisionAllow {
		return true, nil
	}
	return false, writeToolDecision(protocolOut, id, assessment, false)
}

type toolCall struct {
	Name      string
	Arguments map[string]any
	Meta      map[string]any
}

func decodeToolCall(raw json.RawMessage) (toolCall, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return toolCall{}, fmt.Errorf("params are required")
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(raw, &params); err != nil {
		return toolCall{}, err
	}
	name := stringValue(params["name"])
	if strings.TrimSpace(name) == "" {
		return toolCall{}, fmt.Errorf("tool name is required")
	}
	arguments := map[string]any{}
	if rawArguments, exists := params["arguments"]; exists {
		if bytes.Equal(bytes.TrimSpace(rawArguments), []byte("null")) || json.Unmarshal(rawArguments, &arguments) != nil {
			return toolCall{}, fmt.Errorf("arguments must be an object")
		}
	}
	meta := map[string]any{}
	if rawMeta, exists := params["_meta"]; exists && !bytes.Equal(bytes.TrimSpace(rawMeta), []byte("null")) {
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			return toolCall{}, fmt.Errorf("_meta must be an object")
		}
	}
	return toolCall{Name: name, Arguments: arguments, Meta: meta}, nil
}

func validateServerMessage(message []byte) error {
	object, err := decodeObject(message)
	if err != nil {
		return fmt.Errorf("upstream MCP server emitted invalid JSON-RPC: %w", err)
	}
	if stringValue(object["jsonrpc"]) != "2.0" {
		return fmt.Errorf("upstream MCP server emitted a message without jsonrpc 2.0")
	}
	if stringValue(object["method"]) != "" {
		return nil
	}
	_, hasID := object["id"]
	_, hasResult := object["result"]
	_, hasError := object["error"]
	if !hasID || hasResult == hasError {
		return fmt.Errorf("upstream MCP server emitted an invalid JSON-RPC response")
	}
	return nil
}

func decodeObject(message []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(message) {
		return nil, fmt.Errorf("message is not valid UTF-8")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(message, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("message must be a JSON object")
	}
	return object, nil
}

func readMessage(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	var message []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(message)+len(fragment) > maxBytes {
			return nil, errMessageTooLarge
		}
		message = append(message, fragment...)
		switch {
		case err == nil:
			return bytes.TrimSuffix(bytes.TrimSuffix(message, []byte("\n")), []byte("\r")), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(message) > 0:
			return message, nil
		default:
			return nil, err
		}
	}
}

func writeMessage(writer io.Writer, message []byte) error {
	payload := make([]byte, 0, len(message)+1)
	payload = append(payload, message...)
	payload = append(payload, '\n')
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func writeProtocolError(writer io.Writer, id json.RawMessage, code int, message string) error {
	if id == nil {
		id = json.RawMessage("null")
	}
	response := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	response.Error.Code = code
	response.Error.Message = message
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return writeMessage(writer, encoded)
}

func writeToolDecision(writer io.Writer, id json.RawMessage, assessment models.Assessment, auditFailed bool) error {
	text := "Latch blocked this action because it violates security policy."
	switch assessment.DecisionSource {
	case "budget_exhausted":
		text = "Latch blocked this action because the agent's cumulative action budget is exhausted."
	case "budget_store_failure":
		text = "Latch could not safely verify cumulative action state, so this action was blocked."
	}
	if assessment.Decision == models.DecisionRequireApproval {
		text = "Latch requires human approval before this action can run."
	}
	if auditFailed {
		text = "Latch could not safely audit this action, so it was blocked."
	}
	response := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			Content []map[string]string `json:"content"`
			IsError bool                `json:"isError"`
			Meta    map[string]any      `json:"_meta"`
		} `json:"result"`
	}{JSONRPC: "2.0", ID: id}
	response.Result.Content = []map[string]string{{"type": "text", "text": text}}
	response.Result.IsError = true
	response.Result.Meta = map[string]any{
		"io.latch/security": map[string]any{
			"decision":             assessment.Decision,
			"decision_source":      assessment.DecisionSource,
			"risk_level":           assessment.RiskLevel,
			"risk_score":           assessment.RiskScore,
			"hard_deny":            assessment.HardDeny,
			"unsafe_override":      assessment.UnsafeOverride,
			"identity_verified":    assessment.IdentityVerified,
			"identity_source":      assessment.IdentitySource,
			"canonical_agent_id":   assessment.CanonicalAgentID,
			"matched_capabilities": assessment.MatchedCapabilities,
			"budgets":              assessment.Budgets,
		},
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return writeMessage(writer, encoded)
}

func stringValue(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func validRequestID(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	switch value.(type) {
	case string, float64:
		return append(json.RawMessage(nil), raw...)
	default:
		return nil
	}
}

func validResponseID(raw json.RawMessage) json.RawMessage {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return json.RawMessage("null")
	}
	return validRequestID(raw)
}

type sessionIdentity struct {
	mu               sync.RWMutex
	configured       string
	discovered       string
	discoveredSource string
}

func (s *sessionIdentity) identityContext() models.IdentityContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.configured != "" {
		return models.IdentityContext{ID: s.configured, Verified: true, Source: "operator_config"}
	}
	if s.discovered != "" {
		return models.IdentityContext{ID: s.discovered, Verified: false, Source: s.discoveredSource}
	}
	return models.IdentityContext{ID: "mcp-client", Verified: false, Source: "mcp_default"}
}

func (s *sessionIdentity) observeInitialize(raw json.RawMessage) {
	var params struct {
		ClientInfo struct {
			Name string `json:"name"`
		} `json:"clientInfo"`
	}
	if json.Unmarshal(raw, &params) == nil {
		s.setDiscovered(params.ClientInfo.Name, "mcp_initialize")
	}
}

func (s *sessionIdentity) observeRequestMeta(meta map[string]any) {
	for _, key := range []string{"io.modelcontextprotocol/clientInfo", "clientInfo"} {
		value, ok := meta[key].(map[string]any)
		if !ok {
			continue
		}
		if name, ok := value["name"].(string); ok {
			s.setDiscovered(name, "mcp_request_meta")
			return
		}
	}
}

func (s *sessionIdentity) setDiscovered(value, source string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.discovered == "" {
		s.discovered = value
		s.discoveredSource = source
	}
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(payload)
}

func normalizeProcessError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("upstream MCP server exited: %w", err)
}

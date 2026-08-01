// Package mcpadapter contains transport-neutral MCP enforcement behavior.
package mcpadapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/normalize"
	"github.com/princebabou/Latch/internal/strictjson"
	"github.com/princebabou/Latch/pkg/models"
)

// Inspector applies Latch to MCP client messages before a transport forwards
// them. All transports share this implementation so their security semantics
// cannot drift.
type Inspector struct {
	service     *decision.Service
	transport   string
	diagnostics io.Writer
}

// Outcome tells a transport whether it may forward a message. Response is a
// complete JSON-RPC object when Latch handled the request locally.
type Outcome struct {
	Forward  bool
	Response []byte
	Method   string
}

func NewInspector(service *decision.Service, transport string, diagnostics io.Writer) (*Inspector, error) {
	if service == nil {
		return nil, fmt.Errorf("decision service is required")
	}
	transport = strings.TrimSpace(transport)
	if transport == "" {
		return nil, fmt.Errorf("MCP transport name is required")
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	return &Inspector{service: service, transport: transport, diagnostics: diagnostics}, nil
}

// Inspect validates one MCP JSON-RPC object and enforces tools/call. Methods
// other than tools/call remain transparent after base protocol validation.
func (i *Inspector) Inspect(session *Session, message []byte) (Outcome, error) {
	if session == nil {
		return Outcome{}, fmt.Errorf("MCP session is required")
	}
	object, err := DecodeObject(message)
	if err != nil {
		response, marshalErr := ProtocolError(nil, -32700, "Latch: invalid JSON-RPC message")
		return Outcome{Response: response}, marshalErr
	}
	if stringValue(object["jsonrpc"]) != "2.0" {
		response, marshalErr := ProtocolError(validResponseID(object["id"]), -32600, "Latch: invalid JSON-RPC request")
		return Outcome{Response: response}, marshalErr
	}
	method := stringValue(object["method"])
	if method == "initialize" {
		session.observeInitialize(object["params"])
		return Outcome{Forward: true, Method: method}, nil
	}
	if method != "tools/call" {
		return Outcome{Forward: true, Method: method}, nil
	}

	id := validRequestID(object["id"])
	if id == nil {
		response, marshalErr := ProtocolError(nil, -32600, "Latch: tools/call requires a valid request id")
		return Outcome{Response: response, Method: method}, marshalErr
	}
	call, err := decodeToolCall(object["params"])
	if err != nil {
		response, marshalErr := ProtocolError(id, -32602, "Latch: invalid tools/call parameters")
		return Outcome{Response: response, Method: method}, marshalErr
	}
	session.observeRequestMeta(call.Meta)
	identity := session.Identity()
	action, err := normalize.Action(normalize.Request{
		AgentID:   identity.ID,
		Tool:      call.Name,
		Arguments: call.Arguments,
		Metadata: map[string]any{
			"protocol":          "mcp",
			"transport":         i.transport,
			"method":            "tools/call",
			"identity_verified": identity.Verified,
			"identity_source":   identity.Source,
		},
	})
	if err != nil {
		response, marshalErr := ProtocolError(id, -32602, "Latch: invalid tools/call parameters")
		return Outcome{Response: response, Method: method}, marshalErr
	}

	result := i.service.Decide(action, identity)
	if diagnostic := decision.Diagnostic(result); diagnostic != "" {
		fmt.Fprintln(i.diagnostics, diagnostic)
	}
	if i.service.Policy.Audit.Terminal {
		fmt.Fprintln(i.diagnostics, audit.Terminal(result.Event))
	}
	if result.Assessment.Decision == models.DecisionAllow {
		return Outcome{Forward: true, Method: method}, nil
	}
	response, err := toolDecision(id, result.Assessment, result.Assessment.DecisionSource == "audit_failure")
	return Outcome{Response: response, Method: method}, err
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
	if err := json.Unmarshal(raw, &params); err != nil || params == nil {
		return toolCall{}, fmt.Errorf("params must be an object")
	}
	name := stringValue(params["name"])
	if strings.TrimSpace(name) == "" {
		return toolCall{}, fmt.Errorf("tool name is required")
	}
	arguments := map[string]any{}
	if rawArguments, exists := params["arguments"]; exists {
		if bytes.Equal(bytes.TrimSpace(rawArguments), []byte("null")) || json.Unmarshal(rawArguments, &arguments) != nil || arguments == nil {
			return toolCall{}, fmt.Errorf("arguments must be an object")
		}
	}
	meta := map[string]any{}
	if rawMeta, exists := params["_meta"]; exists && !bytes.Equal(bytes.TrimSpace(rawMeta), []byte("null")) {
		if err := json.Unmarshal(rawMeta, &meta); err != nil || meta == nil {
			return toolCall{}, fmt.Errorf("_meta must be an object")
		}
	}
	return toolCall{Name: name, Arguments: arguments, Meta: meta}, nil
}

// ValidateServerMessage rejects invalid upstream JSON-RPC output before a
// framing transport exposes it to the MCP client.
func ValidateServerMessage(message []byte) error {
	object, err := DecodeObject(message)
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

// DecodeObject parses exactly one UTF-8 JSON object.
func DecodeObject(message []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := strictjson.Decode(message, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("message must be a JSON object")
	}
	return object, nil
}

// ProtocolError creates a complete JSON-RPC error object suitable for either
// stdio framing or an application/json HTTP response.
func ProtocolError(id json.RawMessage, code int, message string) ([]byte, error) {
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
	return json.Marshal(response)
}

func toolDecision(id json.RawMessage, assessment models.Assessment, auditFailed bool) ([]byte, error) {
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
	return json.Marshal(response)
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

// Session tracks identity evidence discovered within one MCP session.
type Session struct {
	mu               sync.RWMutex
	configured       string
	discovered       string
	discoveredSource string
}

func NewSession(configuredAgent string) *Session {
	return &Session{configured: strings.TrimSpace(configuredAgent)}
}

func (s *Session) Identity() models.IdentityContext {
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

func (s *Session) observeInitialize(raw json.RawMessage) {
	var params struct {
		ClientInfo struct {
			Name string `json:"name"`
		} `json:"clientInfo"`
	}
	if json.Unmarshal(raw, &params) == nil {
		s.setDiscovered(params.ClientInfo.Name, "mcp_initialize")
	}
}

func (s *Session) observeRequestMeta(meta map[string]any) {
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

func (s *Session) setDiscovered(value, source string) {
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

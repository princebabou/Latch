package latch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/princebabou/Latch/internal/strictjson"
	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	defaultAnthropicMaxCalls       = 128
	defaultAnthropicMaxInputBytes  = 1 << 20
	defaultAnthropicMaxOutputBytes = 4 << 20
	defaultAnthropicReplayCapacity = 10_000
)

// AnthropicDecisionClient is implemented by Client and keeps the adapter
// testable without a live server.
type AnthropicDecisionClient interface {
	Decide(context.Context, api.Action) (api.DecisionResponse, error)
}

// AnthropicToolHandler runs only after every tool_use block in the message is
// allowed by Latch.
type AnthropicToolHandler func(context.Context, map[string]any) (any, error)

type AnthropicAdapterOption func(*AnthropicToolAdapter) error

func WithAnthropicMaxCalls(limit int) AnthropicAdapterOption {
	return func(adapter *AnthropicToolAdapter) error {
		if limit < 1 || limit > 1024 {
			return fmt.Errorf("Anthropic max calls must be between 1 and 1024")
		}
		adapter.maxCalls = limit
		return nil
	}
}

func WithAnthropicMaxInputBytes(limit int) AnthropicAdapterOption {
	return func(adapter *AnthropicToolAdapter) error {
		if limit < 1 || limit > 16<<20 {
			return fmt.Errorf("Anthropic input limit must be between 1 and 16777216 bytes")
		}
		adapter.maxInputBytes = limit
		return nil
	}
}

func WithAnthropicMaxOutputBytes(limit int) AnthropicAdapterOption {
	return func(adapter *AnthropicToolAdapter) error {
		if limit < 1 || limit > 64<<20 {
			return fmt.Errorf("Anthropic output limit must be between 1 and 67108864 bytes")
		}
		adapter.maxOutputBytes = limit
		return nil
	}
}

func WithAnthropicReplayCapacity(capacity int) AnthropicAdapterOption {
	return func(adapter *AnthropicToolAdapter) error {
		if capacity < 128 || capacity > 1_000_000 {
			return fmt.Errorf("Anthropic replay capacity must be between 128 and 1000000")
		}
		adapter.replayCapacity = capacity
		return nil
	}
}

// AnthropicToolAdapter protects tool_use blocks from a completed Anthropic
// Messages API response without depending on a particular Anthropic SDK.
type AnthropicToolAdapter struct {
	client         AnthropicDecisionClient
	handlers       map[string]AnthropicToolHandler
	maxCalls       int
	maxInputBytes  int
	maxOutputBytes int
	replayCapacity int
	replayMu       sync.Mutex
	replayed       map[string]struct{}
	replayOrder    []string
}

func NewAnthropicToolAdapter(client AnthropicDecisionClient, handlers map[string]AnthropicToolHandler, options ...AnthropicAdapterOption) (*AnthropicToolAdapter, error) {
	if client == nil {
		return nil, fmt.Errorf("Latch decision client cannot be nil")
	}
	adapter := &AnthropicToolAdapter{
		client: client, handlers: make(map[string]AnthropicToolHandler, len(handlers)),
		maxCalls: defaultAnthropicMaxCalls, maxInputBytes: defaultAnthropicMaxInputBytes,
		maxOutputBytes: defaultAnthropicMaxOutputBytes, replayCapacity: defaultAnthropicReplayCapacity,
		replayed: make(map[string]struct{}),
	}
	for name, handler := range handlers {
		if err := validateAnthropicName(name); err != nil {
			return nil, fmt.Errorf("invalid Anthropic handler: %w", err)
		}
		if handler == nil {
			return nil, fmt.Errorf("Anthropic handler %q cannot be nil", name)
		}
		adapter.handlers[name] = handler
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("Anthropic adapter option cannot be nil")
		}
		if err := option(adapter); err != nil {
			return nil, err
		}
	}
	if adapter.replayCapacity < adapter.maxCalls {
		return nil, fmt.Errorf("Anthropic replay capacity cannot be smaller than max calls")
	}
	return adapter, nil
}

// AnthropicToolResult is one tool_result content block. Append the returned
// slice to a new user message and send it back to the model.
type AnthropicToolResult struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

type anthropicToolUse struct {
	ID    string
	Name  string
	Input map[string]any
}

// ExecuteMessage accepts one completed Anthropic Messages API response JSON
// value and protects every tool_use content block. Every block is parsed,
// resolved to a handler, and allowed before any handler runs.
func (adapter *AnthropicToolAdapter) ExecuteMessage(ctx context.Context, payload []byte) ([]AnthropicToolResult, error) {
	var response struct {
		Type       string `json:"type"`
		Role       string `json:"role"`
		StopReason string `json:"stop_reason"`
		Content    *[]struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := strictjson.Decode(payload, &response); err != nil {
		return nil, &AnthropicProtocolError{Message: "Messages payload is not strict JSON: " + err.Error()}
	}
	if response.Type != "" && response.Type != "message" {
		return nil, &AnthropicProtocolError{Message: "payload is not a Messages API message"}
	}
	if response.Role != "" && response.Role != "assistant" {
		return nil, &AnthropicProtocolError{Message: "only assistant messages carry tool_use blocks"}
	}
	if response.Content == nil {
		return nil, &AnthropicProtocolError{Message: "Messages payload is missing content"}
	}
	calls := make([]anthropicToolUse, 0)
	for _, block := range *response.Content {
		if block.Type != "tool_use" {
			continue
		}
		call, err := adapter.parseToolUse(block.ID, block.Name, block.Input)
		if err != nil {
			return nil, err
		}
		calls = append(calls, call)
	}
	results, err := adapter.execute(ctx, calls)
	if err != nil {
		return nil, err
	}
	outputs := make([]AnthropicToolResult, len(calls))
	for index, call := range calls {
		outputs[index] = AnthropicToolResult{Type: "tool_result", ToolUseID: call.ID, Content: results[index]}
	}
	return outputs, nil
}

func (adapter *AnthropicToolAdapter) parseToolUse(id, name string, rawInput json.RawMessage) (anthropicToolUse, error) {
	if err := validateAnthropicID(id); err != nil {
		return anthropicToolUse{}, &AnthropicProtocolError{Message: err.Error()}
	}
	if err := validateAnthropicName(name); err != nil {
		return anthropicToolUse{}, &AnthropicProtocolError{Message: err.Error()}
	}
	if len(rawInput) == 0 {
		return anthropicToolUse{}, &AnthropicProtocolError{Message: fmt.Sprintf("tool_use %q is missing input", id)}
	}
	if len(rawInput) > adapter.maxInputBytes {
		return anthropicToolUse{}, &AnthropicProtocolError{Message: fmt.Sprintf("input for tool_use %q exceeds %d bytes", id, adapter.maxInputBytes)}
	}
	var input map[string]any
	if err := strictjson.Decode(rawInput, &input); err != nil || input == nil {
		if err == nil {
			err = fmt.Errorf("value is not an object")
		}
		return anthropicToolUse{}, &AnthropicProtocolError{Message: fmt.Sprintf("input for tool_use %q is invalid: %v", id, err)}
	}
	if err := validateOpenAIJSON(input); err != nil {
		return anthropicToolUse{}, &AnthropicProtocolError{Message: fmt.Sprintf("input for tool_use %q is invalid: %v", id, err)}
	}
	return anthropicToolUse{ID: id, Name: name, Input: input}, nil
}

func (adapter *AnthropicToolAdapter) execute(ctx context.Context, calls []anthropicToolUse) ([]string, error) {
	if len(calls) > adapter.maxCalls {
		return nil, &AnthropicProtocolError{Message: fmt.Sprintf("tool_use batch exceeds %d blocks", adapter.maxCalls)}
	}
	seen := make(map[string]struct{}, len(calls))
	for _, call := range calls {
		if _, duplicate := seen[call.ID]; duplicate {
			return nil, &AnthropicReplayError{ToolUseID: call.ID}
		}
		seen[call.ID] = struct{}{}
		if _, exists := adapter.handlers[call.Name]; !exists {
			return nil, &UnknownAnthropicToolError{ToolUseID: call.ID, Tool: call.Name}
		}
	}
	for _, call := range calls {
		decision, err := adapter.client.Decide(ctx, api.Action{
			Tool: call.Name, Arguments: call.Input,
			Metadata: map[string]any{
				"protocol": "anthropic-messages", "surface": "messages",
				"tool_use_id": call.ID, "tool_call_kind": "tool_use",
			},
		})
		if err != nil {
			return nil, err
		}
		if decision.Decision != models.DecisionAllow || decision.FailClosed {
			return nil, &AnthropicToolNotAllowedError{ToolUseID: call.ID, Tool: call.Name, Response: decision}
		}
	}
	if err := adapter.reserve(calls); err != nil {
		return nil, err
	}
	results := make([]string, len(calls))
	for index, call := range calls {
		value, err := adapter.handlers[call.Name](ctx, call.Input)
		if err != nil {
			return nil, &AnthropicToolExecutionError{ToolUseID: call.ID, Tool: call.Name, Cause: err}
		}
		encoded, err := encodeOpenAIToolOutput(value, adapter.maxOutputBytes)
		if err != nil {
			return nil, &AnthropicToolExecutionError{ToolUseID: call.ID, Tool: call.Name, Cause: err}
		}
		results[index] = encoded
	}
	return results, nil
}

func (adapter *AnthropicToolAdapter) reserve(calls []anthropicToolUse) error {
	adapter.replayMu.Lock()
	defer adapter.replayMu.Unlock()
	for _, call := range calls {
		if _, exists := adapter.replayed[call.ID]; exists {
			return &AnthropicReplayError{ToolUseID: call.ID}
		}
	}
	for _, call := range calls {
		adapter.replayed[call.ID] = struct{}{}
		adapter.replayOrder = append(adapter.replayOrder, call.ID)
	}
	for len(adapter.replayOrder) > adapter.replayCapacity {
		oldest := adapter.replayOrder[0]
		adapter.replayOrder = adapter.replayOrder[1:]
		delete(adapter.replayed, oldest)
	}
	return nil
}

func validateAnthropicID(value string) error {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return fmt.Errorf("tool_use id must be 1-256 UTF-8 bytes")
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("tool_use id must contain visible ASCII only")
		}
	}
	return nil
}

func validateAnthropicName(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > 256 || !utf8.ValidString(value) || strings.ContainsRune(value, utf8.RuneError) {
		return fmt.Errorf("tool name must be 1-256 UTF-8 bytes")
	}
	return nil
}

type AnthropicProtocolError struct{ Message string }

func (err *AnthropicProtocolError) Error() string {
	return "invalid Anthropic tool call; action not executed: " + err.Message
}

type UnknownAnthropicToolError struct{ ToolUseID, Tool string }

func (err *UnknownAnthropicToolError) Error() string {
	return fmt.Sprintf("Anthropic tool %q for tool_use %q has no registered handler; batch not executed", err.Tool, err.ToolUseID)
}

type AnthropicReplayError struct{ ToolUseID string }

func (err *AnthropicReplayError) Error() string {
	return fmt.Sprintf("Anthropic tool_use %q was duplicated or replayed; batch not executed", err.ToolUseID)
}

type AnthropicToolNotAllowedError struct {
	ToolUseID string
	Tool      string
	Response  api.DecisionResponse
}

func (err *AnthropicToolNotAllowedError) Error() string {
	return fmt.Sprintf("Latch decision for Anthropic tool %q tool_use %q is %s; batch not executed", err.Tool, err.ToolUseID, err.Response.Decision)
}

type AnthropicToolExecutionError struct {
	ToolUseID string
	Tool      string
	Cause     error
}

func (err *AnthropicToolExecutionError) Error() string {
	return fmt.Sprintf("execute Anthropic tool %q tool_use %q: %v", err.Tool, err.ToolUseID, err.Cause)
}
func (err *AnthropicToolExecutionError) Unwrap() error { return err.Cause }

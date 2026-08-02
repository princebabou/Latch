package latch

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/princebabou/Latch/internal/strictjson"
	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	defaultOpenAIMaxCalls       = 128
	defaultOpenAIMaxArguments   = 1 << 20
	defaultOpenAIMaxOutput      = 4 << 20
	defaultOpenAIReplayCapacity = 10_000
)

// OpenAIDecisionClient is implemented by Client and makes the adapter easy to test.
type OpenAIDecisionClient interface {
	Decide(context.Context, api.Action) (api.DecisionResponse, error)
}

// OpenAIToolHandler runs only after every tool call in the selected batch is allowed.
type OpenAIToolHandler func(context.Context, map[string]any) (any, error)

type OpenAIAdapterOption func(*OpenAIToolAdapter) error

func WithOpenAIMaxCalls(limit int) OpenAIAdapterOption {
	return func(adapter *OpenAIToolAdapter) error {
		if limit < 1 || limit > 1024 {
			return fmt.Errorf("OpenAI max calls must be between 1 and 1024")
		}
		adapter.maxCalls = limit
		return nil
	}
}

func WithOpenAIMaxArgumentBytes(limit int) OpenAIAdapterOption {
	return func(adapter *OpenAIToolAdapter) error {
		if limit < 1 || limit > 16<<20 {
			return fmt.Errorf("OpenAI argument limit must be between 1 and 16777216 bytes")
		}
		adapter.maxArgumentBytes = limit
		return nil
	}
}

func WithOpenAIMaxOutputBytes(limit int) OpenAIAdapterOption {
	return func(adapter *OpenAIToolAdapter) error {
		if limit < 1 || limit > 64<<20 {
			return fmt.Errorf("OpenAI output limit must be between 1 and 67108864 bytes")
		}
		adapter.maxOutputBytes = limit
		return nil
	}
}

func WithOpenAIReplayCapacity(capacity int) OpenAIAdapterOption {
	return func(adapter *OpenAIToolAdapter) error {
		if capacity < 128 || capacity > 1_000_000 {
			return fmt.Errorf("OpenAI replay capacity must be between 128 and 1000000")
		}
		adapter.replayCapacity = capacity
		return nil
	}
}

// OpenAIToolAdapter protects completed OpenAI Responses API and Chat
// Completions function calls without depending on a particular OpenAI SDK.
type OpenAIToolAdapter struct {
	client           OpenAIDecisionClient
	handlers         map[string]OpenAIToolHandler
	maxCalls         int
	maxArgumentBytes int
	maxOutputBytes   int
	replayCapacity   int
	replayMu         sync.Mutex
	replayed         map[string]struct{}
	replayOrder      []string
}

func NewOpenAIToolAdapter(client OpenAIDecisionClient, handlers map[string]OpenAIToolHandler, options ...OpenAIAdapterOption) (*OpenAIToolAdapter, error) {
	if client == nil {
		return nil, fmt.Errorf("Latch decision client cannot be nil")
	}
	adapter := &OpenAIToolAdapter{
		client: client, handlers: make(map[string]OpenAIToolHandler, len(handlers)),
		maxCalls: defaultOpenAIMaxCalls, maxArgumentBytes: defaultOpenAIMaxArguments,
		maxOutputBytes: defaultOpenAIMaxOutput, replayCapacity: defaultOpenAIReplayCapacity,
		replayed: make(map[string]struct{}),
	}
	for name, handler := range handlers {
		if err := validateOpenAIName(name); err != nil {
			return nil, fmt.Errorf("invalid OpenAI handler: %w", err)
		}
		if handler == nil {
			return nil, fmt.Errorf("OpenAI handler %q cannot be nil", name)
		}
		adapter.handlers[name] = handler
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("OpenAI adapter option cannot be nil")
		}
		if err := option(adapter); err != nil {
			return nil, err
		}
	}
	if adapter.replayCapacity < adapter.maxCalls {
		return nil, fmt.Errorf("OpenAI replay capacity cannot be smaller than max calls")
	}
	return adapter, nil
}

type OpenAIResponseToolOutput struct {
	Type   string `json:"type"`
	CallID string `json:"call_id"`
	Output string `json:"output"`
}

type OpenAIChatToolMessage struct {
	Role       string `json:"role"`
	ToolCallID string `json:"tool_call_id"`
	Content    string `json:"content"`
}

type openAIToolCall struct {
	ID        string
	Name      string
	Arguments map[string]any
	Surface   string
}

// ExecuteResponses accepts one completed Responses API response JSON value.
// The returned outputs should be appended to the next input alongside the
// original response output items.
func (adapter *OpenAIToolAdapter) ExecuteResponses(ctx context.Context, payload []byte) ([]OpenAIResponseToolOutput, error) {
	var response struct {
		Status string `json:"status"`
		Output *[]struct {
			Type      string `json:"type"`
			CallID    string `json:"call_id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
			Status    string `json:"status"`
		} `json:"output"`
	}
	if err := strictjson.Decode(payload, &response); err != nil {
		return nil, &OpenAIProtocolError{Message: "Responses payload is not strict JSON: " + err.Error()}
	}
	if response.Status != "" && response.Status != "completed" {
		return nil, &OpenAIProtocolError{Message: "Responses payload must be completed before execution"}
	}
	if response.Output == nil {
		return nil, &OpenAIProtocolError{Message: "Responses payload is missing output"}
	}
	calls := make([]openAIToolCall, 0)
	for _, item := range *response.Output {
		switch item.Type {
		case "function_call":
			if item.Status != "" && item.Status != "completed" {
				return nil, &OpenAIProtocolError{Message: "function call must be completed before execution"}
			}
			call, err := adapter.parseCall(item.CallID, item.Name, item.Arguments, "responses")
			if err != nil {
				return nil, err
			}
			calls = append(calls, call)
		case "custom_tool_call":
			return nil, &OpenAIProtocolError{Message: "custom tools are not supported by this function-tool adapter"}
		}
	}
	results, err := adapter.execute(ctx, calls)
	if err != nil {
		return nil, err
	}
	outputs := make([]OpenAIResponseToolOutput, len(calls))
	for index, call := range calls {
		outputs[index] = OpenAIResponseToolOutput{Type: "function_call_output", CallID: call.ID, Output: results[index]}
	}
	return outputs, nil
}

// ExecuteChatCompletion accepts one completed Chat Completion JSON value and
// protects function calls from the selected choice (choice 0 by default).
func (adapter *OpenAIToolAdapter) ExecuteChatCompletion(ctx context.Context, payload []byte, choiceIndex ...int) ([]OpenAIChatToolMessage, error) {
	var response struct {
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := strictjson.Decode(payload, &response); err != nil {
		return nil, &OpenAIProtocolError{Message: "Chat Completions payload is not strict JSON: " + err.Error()}
	}
	selected := 0
	if len(choiceIndex) > 1 {
		return nil, &OpenAIProtocolError{Message: "at most one choice index may be selected"}
	}
	if len(choiceIndex) == 1 {
		selected = choiceIndex[0]
	}
	var toolCallsFound bool
	calls := make([]openAIToolCall, 0)
	for _, choice := range response.Choices {
		if choice.Index != selected {
			continue
		}
		toolCallsFound = true
		for _, item := range choice.Message.ToolCalls {
			if item.Type != "function" {
				return nil, &OpenAIProtocolError{Message: fmt.Sprintf("unsupported Chat Completions tool call type %q", item.Type)}
			}
			call, err := adapter.parseCall(item.ID, item.Function.Name, item.Function.Arguments, "chat_completions")
			if err != nil {
				return nil, err
			}
			calls = append(calls, call)
		}
		break
	}
	if !toolCallsFound {
		return nil, &OpenAIProtocolError{Message: fmt.Sprintf("Chat Completions choice %d was not found", selected)}
	}
	results, err := adapter.execute(ctx, calls)
	if err != nil {
		return nil, err
	}
	messages := make([]OpenAIChatToolMessage, len(calls))
	for index, call := range calls {
		messages[index] = OpenAIChatToolMessage{Role: "tool", ToolCallID: call.ID, Content: results[index]}
	}
	return messages, nil
}

func (adapter *OpenAIToolAdapter) parseCall(id, name, rawArguments, surface string) (openAIToolCall, error) {
	if err := validateOpenAIID(id); err != nil {
		return openAIToolCall{}, &OpenAIProtocolError{Message: err.Error()}
	}
	if err := validateOpenAIName(name); err != nil {
		return openAIToolCall{}, &OpenAIProtocolError{Message: err.Error()}
	}
	if len(rawArguments) > adapter.maxArgumentBytes {
		return openAIToolCall{}, &OpenAIProtocolError{Message: fmt.Sprintf("arguments for call %q exceed %d bytes", id, adapter.maxArgumentBytes)}
	}
	var arguments map[string]any
	if err := strictjson.Decode([]byte(rawArguments), &arguments); err != nil || arguments == nil {
		if err == nil {
			err = fmt.Errorf("value is not an object")
		}
		return openAIToolCall{}, &OpenAIProtocolError{Message: fmt.Sprintf("arguments for call %q are invalid: %v", id, err)}
	}
	if err := validateOpenAIJSON(arguments); err != nil {
		return openAIToolCall{}, &OpenAIProtocolError{Message: fmt.Sprintf("arguments for call %q are invalid: %v", id, err)}
	}
	return openAIToolCall{ID: id, Name: name, Arguments: arguments, Surface: surface}, nil
}

func (adapter *OpenAIToolAdapter) execute(ctx context.Context, calls []openAIToolCall) ([]string, error) {
	if len(calls) > adapter.maxCalls {
		return nil, &OpenAIProtocolError{Message: fmt.Sprintf("tool call batch exceeds %d calls", adapter.maxCalls)}
	}
	seen := make(map[string]struct{}, len(calls))
	for _, call := range calls {
		if _, duplicate := seen[call.ID]; duplicate {
			return nil, &OpenAIReplayError{CallID: call.ID}
		}
		seen[call.ID] = struct{}{}
		if _, exists := adapter.handlers[call.Name]; !exists {
			return nil, &UnknownOpenAIToolError{CallID: call.ID, Tool: call.Name}
		}
	}
	for _, call := range calls {
		decision, err := adapter.client.Decide(ctx, api.Action{
			Tool: call.Name, Arguments: call.Arguments,
			Metadata: map[string]any{
				"protocol": "openai-compatible", "surface": call.Surface,
				"tool_call_id": call.ID, "tool_call_kind": "function",
			},
		})
		if err != nil {
			return nil, err
		}
		if decision.Decision != models.DecisionAllow || decision.FailClosed {
			return nil, &OpenAIToolNotAllowedError{CallID: call.ID, Tool: call.Name, Response: decision}
		}
	}
	if err := adapter.reserve(calls); err != nil {
		return nil, err
	}
	results := make([]string, len(calls))
	for index, call := range calls {
		value, err := adapter.handlers[call.Name](ctx, call.Arguments)
		if err != nil {
			return nil, &OpenAIToolExecutionError{CallID: call.ID, Tool: call.Name, Cause: err}
		}
		encoded, err := encodeOpenAIToolOutput(value, adapter.maxOutputBytes)
		if err != nil {
			return nil, &OpenAIToolExecutionError{CallID: call.ID, Tool: call.Name, Cause: err}
		}
		results[index] = encoded
	}
	return results, nil
}

func (adapter *OpenAIToolAdapter) reserve(calls []openAIToolCall) error {
	adapter.replayMu.Lock()
	defer adapter.replayMu.Unlock()
	for _, call := range calls {
		if _, exists := adapter.replayed[call.ID]; exists {
			return &OpenAIReplayError{CallID: call.ID}
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

func encodeOpenAIToolOutput(value any, limit int) (string, error) {
	if text, ok := value.(string); ok {
		if len(text) > limit {
			return "", fmt.Errorf("tool output exceeds %d bytes", limit)
		}
		return text, nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode tool output: %w", err)
	}
	if len(payload) > limit {
		return "", fmt.Errorf("tool output exceeds %d bytes", limit)
	}
	return string(payload), nil
}

func validateOpenAIID(value string) error {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return fmt.Errorf("tool call id must be 1-256 UTF-8 bytes")
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("tool call id must contain visible ASCII only")
		}
	}
	return nil
}

func validateOpenAIName(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > 256 || !utf8.ValidString(value) || strings.ContainsRune(value, utf8.RuneError) {
		return fmt.Errorf("function name must be 1-256 UTF-8 bytes")
	}
	return nil
}

func validateOpenAIJSON(value any) error {
	switch typed := value.(type) {
	case nil, bool:
		return nil
	case string:
		if strings.ContainsRune(typed, utf8.RuneError) {
			return fmt.Errorf("JSON strings cannot contain replacement or unpaired-surrogate characters")
		}
		return nil
	case json.Number:
		text := string(typed)
		if strings.ContainsAny(text, ".eE") {
			parsed, err := strconv.ParseFloat(text, 64)
			if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
				return fmt.Errorf("JSON number is outside the finite range")
			}
			if parsed == math.Trunc(parsed) && (parsed < -9_007_199_254_740_991 || parsed > 9_007_199_254_740_991) {
				return fmt.Errorf("JSON integer-valued number is outside the interoperable safe range")
			}
			return nil
		}
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil || parsed < -9_007_199_254_740_991 || parsed > 9_007_199_254_740_991 {
			return fmt.Errorf("JSON integer is outside the interoperable safe range")
		}
		return nil
	case []any:
		for _, item := range typed {
			if err := validateOpenAIJSON(item); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for key, item := range typed {
			if strings.ContainsRune(key, utf8.RuneError) {
				return fmt.Errorf("JSON object keys cannot contain replacement or unpaired-surrogate characters")
			}
			if err := validateOpenAIJSON(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
}

type OpenAIProtocolError struct{ Message string }

func (err *OpenAIProtocolError) Error() string {
	return "invalid OpenAI tool call; action not executed: " + err.Message
}

type UnknownOpenAIToolError struct{ CallID, Tool string }

func (err *UnknownOpenAIToolError) Error() string {
	return fmt.Sprintf("OpenAI tool %q for call %q has no registered handler; batch not executed", err.Tool, err.CallID)
}

type OpenAIReplayError struct{ CallID string }

func (err *OpenAIReplayError) Error() string {
	return fmt.Sprintf("OpenAI tool call %q was duplicated or replayed; batch not executed", err.CallID)
}

type OpenAIToolNotAllowedError struct {
	CallID   string
	Tool     string
	Response api.DecisionResponse
}

func (err *OpenAIToolNotAllowedError) Error() string {
	return fmt.Sprintf("Latch decision for OpenAI tool %q call %q is %s; batch not executed", err.Tool, err.CallID, err.Response.Decision)
}

type OpenAIToolExecutionError struct {
	CallID string
	Tool   string
	Cause  error
}

func (err *OpenAIToolExecutionError) Error() string {
	return fmt.Sprintf("execute OpenAI tool %q call %q: %v", err.Tool, err.CallID, err.Cause)
}
func (err *OpenAIToolExecutionError) Unwrap() error { return err.Cause }

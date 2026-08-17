package latch

import (
	"context"
	"errors"
	"reflect"
	"testing"

	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

type fakeAnthropicClient struct {
	decisions []models.Decision
	actions   []api.Action
	err       error
}

func (client *fakeAnthropicClient) Decide(_ context.Context, action api.Action) (api.DecisionResponse, error) {
	client.actions = append(client.actions, action)
	if client.err != nil {
		return api.DecisionResponse{}, client.err
	}
	decision := models.DecisionAllow
	if len(client.decisions) >= len(client.actions) {
		decision = client.decisions[len(client.actions)-1]
	}
	return api.DecisionResponse{Decision: decision}, nil
}

func TestAnthropicExecutesAllowedToolUse(t *testing.T) {
	client := &fakeAnthropicClient{}
	var received map[string]any
	adapter, err := NewAnthropicToolAdapter(client, map[string]AnthropicToolHandler{
		"weather": func(_ context.Context, input map[string]any) (any, error) {
			received = input
			return map[string]any{"temperature": 24}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := adapter.ExecuteMessage(context.Background(), []byte(`{
		"type":"message","role":"assistant","stop_reason":"tool_use","content":[
			{"type":"text","text":"Let me check."},
			{"type":"tool_use","id":"toolu_123","name":"weather","input":{"city":"Kigali"}}
		]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []AnthropicToolResult{{Type: "tool_result", ToolUseID: "toolu_123", Content: `{"temperature":24}`}}
	if !reflect.DeepEqual(outputs, want) {
		t.Fatalf("outputs = %#v, want %#v", outputs, want)
	}
	if received["city"] != "Kigali" || len(client.actions) != 1 {
		t.Fatalf("handler input/actions = %#v / %#v", received, client.actions)
	}
	metadata := client.actions[0].Metadata
	if metadata["protocol"] != "anthropic-messages" || metadata["surface"] != "messages" || metadata["tool_use_id"] != "toolu_123" {
		t.Fatalf("unexpected action metadata: %#v", metadata)
	}
}

func TestAnthropicBlocksHeldToolUse(t *testing.T) {
	client := &fakeAnthropicClient{decisions: []models.Decision{models.DecisionBlock}}
	executed := false
	adapter, err := NewAnthropicToolAdapter(client, map[string]AnthropicToolHandler{
		"deploy": func(_ context.Context, _ map[string]any) (any, error) {
			executed = true
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.ExecuteMessage(context.Background(), []byte(`{
		"type":"message","role":"assistant","content":[
			{"type":"tool_use","id":"toolu_deny","name":"deploy","input":{"env":"prod"}}
		]}`))
	var notAllowed *AnthropicToolNotAllowedError
	if !errors.As(err, &notAllowed) {
		t.Fatalf("expected AnthropicToolNotAllowedError, got %v", err)
	}
	if executed {
		t.Fatal("handler ran despite a BLOCK decision")
	}
}

func TestAnthropicRejectsUnknownToolBeforeAnyExecution(t *testing.T) {
	client := &fakeAnthropicClient{}
	ran := false
	adapter, err := NewAnthropicToolAdapter(client, map[string]AnthropicToolHandler{
		"known": func(_ context.Context, _ map[string]any) (any, error) { ran = true; return "ok", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.ExecuteMessage(context.Background(), []byte(`{
		"type":"message","role":"assistant","content":[
			{"type":"tool_use","id":"toolu_a","name":"known","input":{}},
			{"type":"tool_use","id":"toolu_b","name":"unknown","input":{}}
		]}`))
	var unknown *UnknownAnthropicToolError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected UnknownAnthropicToolError, got %v", err)
	}
	if ran || len(client.actions) != 0 {
		t.Fatalf("no handler or decision should run when a tool is unknown: ran=%v actions=%d", ran, len(client.actions))
	}
}

func TestAnthropicRejectsDuplicateToolUseID(t *testing.T) {
	client := &fakeAnthropicClient{}
	adapter, err := NewAnthropicToolAdapter(client, map[string]AnthropicToolHandler{
		"echo": func(_ context.Context, input map[string]any) (any, error) { return input, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.ExecuteMessage(context.Background(), []byte(`{
		"type":"message","role":"assistant","content":[
			{"type":"tool_use","id":"toolu_same","name":"echo","input":{}},
			{"type":"tool_use","id":"toolu_same","name":"echo","input":{}}
		]}`))
	var replay *AnthropicReplayError
	if !errors.As(err, &replay) {
		t.Fatalf("expected AnthropicReplayError, got %v", err)
	}
}

func TestAnthropicReplayAcrossMessages(t *testing.T) {
	client := &fakeAnthropicClient{}
	adapter, err := NewAnthropicToolAdapter(client, map[string]AnthropicToolHandler{
		"echo": func(_ context.Context, input map[string]any) (any, error) { return input, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	message := []byte(`{"type":"message","role":"assistant","content":[{"type":"tool_use","id":"toolu_once","name":"echo","input":{}}]}`)
	if _, err := adapter.ExecuteMessage(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	_, err = adapter.ExecuteMessage(context.Background(), message)
	var replay *AnthropicReplayError
	if !errors.As(err, &replay) {
		t.Fatalf("expected replay to be refused on redelivery, got %v", err)
	}
}

func TestAnthropicRejectsNonAssistantMessage(t *testing.T) {
	client := &fakeAnthropicClient{}
	adapter, err := NewAnthropicToolAdapter(client, map[string]AnthropicToolHandler{
		"echo": func(_ context.Context, input map[string]any) (any, error) { return input, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.ExecuteMessage(context.Background(), []byte(`{"type":"message","role":"user","content":[]}`))
	var protocol *AnthropicProtocolError
	if !errors.As(err, &protocol) {
		t.Fatalf("expected AnthropicProtocolError, got %v", err)
	}
}

func TestAnthropicNoToolUseReturnsEmpty(t *testing.T) {
	client := &fakeAnthropicClient{}
	adapter, err := NewAnthropicToolAdapter(client, map[string]AnthropicToolHandler{
		"echo": func(_ context.Context, input map[string]any) (any, error) { return input, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := adapter.ExecuteMessage(context.Background(), []byte(`{
		"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":"Hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 0 {
		t.Fatalf("expected no tool results, got %#v", outputs)
	}
}

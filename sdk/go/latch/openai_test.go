package latch

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

type fakeOpenAIClient struct {
	decisions []models.Decision
	actions   []api.Action
	err       error
}

func (client *fakeOpenAIClient) Decide(_ context.Context, action api.Action) (api.DecisionResponse, error) {
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

func TestOpenAIResponsesExecutesAllowedFunction(t *testing.T) {
	client := &fakeOpenAIClient{}
	var received map[string]any
	adapter, err := NewOpenAIToolAdapter(client, map[string]OpenAIToolHandler{
		"weather": func(_ context.Context, arguments map[string]any) (any, error) {
			received = arguments
			return map[string]any{"temperature": 24}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := adapter.ExecuteResponses(context.Background(), []byte(`{
		"status":"completed","output":[
			{"type":"reasoning","id":"r1"},
			{"type":"function_call","call_id":"call_123","name":"weather","arguments":"{\"city\":\"Kigali\"}","status":"completed"}
		]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []OpenAIResponseToolOutput{{Type: "function_call_output", CallID: "call_123", Output: `{"temperature":24}`}}
	if !reflect.DeepEqual(outputs, want) {
		t.Fatalf("outputs = %#v, want %#v", outputs, want)
	}
	if received["city"] != "Kigali" || len(client.actions) != 1 {
		t.Fatalf("handler arguments/actions = %#v / %#v", received, client.actions)
	}
	metadata := client.actions[0].Metadata
	if metadata["protocol"] != "openai-compatible" || metadata["surface"] != "responses" || metadata["tool_call_id"] != "call_123" {
		t.Fatalf("unexpected action metadata: %#v", metadata)
	}
}

func TestOpenAIChatUsesSelectedChoice(t *testing.T) {
	client := &fakeOpenAIClient{}
	adapter, err := NewOpenAIToolAdapter(client, map[string]OpenAIToolHandler{
		"lookup": func(_ context.Context, arguments map[string]any) (any, error) { return arguments["value"], nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"choices":[
		{"index":0,"message":{"tool_calls":[{"id":"call_zero","type":"function","function":{"name":"missing","arguments":"{}"}}]}},
		{"index":1,"message":{"tool_calls":[{"id":"call_one","type":"function","function":{"name":"lookup","arguments":"{\"value\":7}"}}]}}
	]}`)
	messages, err := adapter.ExecuteChatCompletion(context.Background(), payload, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []OpenAIChatToolMessage{{Role: "tool", ToolCallID: "call_one", Content: "7"}}
	if !reflect.DeepEqual(messages, want) {
		t.Fatalf("messages = %#v, want %#v", messages, want)
	}
}

func TestOpenAIBatchDenialExecutesNothing(t *testing.T) {
	client := &fakeOpenAIClient{decisions: []models.Decision{models.DecisionAllow, models.DecisionBlock}}
	executions := 0
	handler := func(context.Context, map[string]any) (any, error) { executions++; return "ok", nil }
	adapter, _ := NewOpenAIToolAdapter(client, map[string]OpenAIToolHandler{"first": handler, "second": handler})
	_, err := adapter.ExecuteResponses(context.Background(), []byte(`{"status":"completed","output":[
		{"type":"function_call","call_id":"call_first","name":"first","arguments":"{}"},
		{"type":"function_call","call_id":"call_second","name":"second","arguments":"{}"}
	]}`))
	var denied *OpenAIToolNotAllowedError
	if !errors.As(err, &denied) || executions != 0 || len(client.actions) != 2 {
		t.Fatalf("err/executions/actions = %v / %d / %d", err, executions, len(client.actions))
	}
}

func TestOpenAIRejectsMalformedUnknownAndCustomBeforeExecution(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		target  any
	}{
		{"duplicate arguments", `{"output":[{"type":"function_call","call_id":"call_dup","name":"safe","arguments":"{\"path\":1,\"path\":2}"}]}`, &OpenAIProtocolError{}},
		{"unsafe integer", `{"output":[{"type":"function_call","call_id":"call_number","name":"safe","arguments":"{\"value\":9007199254740992}"}]}`, &OpenAIProtocolError{}},
		{"unknown tool", `{"output":[{"type":"function_call","call_id":"call_unknown","name":"unknown","arguments":"{}"}]}`, &UnknownOpenAIToolError{}},
		{"custom tool", `{"output":[{"type":"custom_tool_call","call_id":"call_custom","name":"shell","input":"echo hi"}]}`, &OpenAIProtocolError{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeOpenAIClient{}
			executions := 0
			adapter, _ := NewOpenAIToolAdapter(client, map[string]OpenAIToolHandler{
				"safe": func(context.Context, map[string]any) (any, error) { executions++; return nil, nil },
			})
			_, err := adapter.ExecuteResponses(context.Background(), []byte(test.payload))
			if err == nil || executions != 0 || len(client.actions) != 0 {
				t.Fatalf("err/executions/actions = %v / %d / %d", err, executions, len(client.actions))
			}
		})
	}
}

func TestOpenAIReplayAndFailureRemainConsumed(t *testing.T) {
	client := &fakeOpenAIClient{}
	executions := 0
	adapter, _ := NewOpenAIToolAdapter(client, map[string]OpenAIToolHandler{
		"write": func(context.Context, map[string]any) (any, error) {
			executions++
			return nil, fmt.Errorf("disk unavailable")
		},
	})
	payload := []byte(`{"output":[{"type":"function_call","call_id":"call_write","name":"write","arguments":"{}"}]}`)
	_, firstErr := adapter.ExecuteResponses(context.Background(), payload)
	var executionError *OpenAIToolExecutionError
	if !errors.As(firstErr, &executionError) {
		t.Fatalf("first error = %v", firstErr)
	}
	_, secondErr := adapter.ExecuteResponses(context.Background(), payload)
	var replayError *OpenAIReplayError
	if !errors.As(secondErr, &replayError) || executions != 1 {
		t.Fatalf("second error/executions = %v / %d", secondErr, executions)
	}
}

func TestOpenAIUnavailableExecutesNothing(t *testing.T) {
	client := &fakeOpenAIClient{err: fmt.Errorf("offline")}
	executions := 0
	adapter, _ := NewOpenAIToolAdapter(client, map[string]OpenAIToolHandler{
		"safe": func(context.Context, map[string]any) (any, error) { executions++; return nil, nil },
	})
	_, err := adapter.ExecuteResponses(context.Background(), []byte(`{"output":[{"type":"function_call","call_id":"call_safe","name":"safe","arguments":"{}"}]}`))
	if err == nil || executions != 0 {
		t.Fatalf("err/executions = %v / %d", err, executions)
	}
}

package normalize

import "testing"

func TestActionUsesStructuredArgumentsBeforeToolNameHeuristics(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		arguments map[string]any
		operation string
	}{
		{name: "database execute tool", tool: "database.execute", arguments: map[string]any{"query": "SELECT 1"}, operation: "query"},
		{name: "generic URL tool", tool: "custom.invoke", arguments: map[string]any{"url": "https://example.test"}, operation: "network"},
		{name: "generic command tool", tool: "custom.invoke", arguments: map[string]any{"command": "npm test"}, operation: "execute"},
		{name: "explicit operation", tool: "custom.invoke", arguments: map[string]any{"operation": "delete"}, operation: "delete"},
		{name: "case-insensitive schema key", tool: "custom.invoke", arguments: map[string]any{"SQL": "SELECT 1"}, operation: "query"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action, err := Action(Request{AgentID: "test", Tool: test.tool, Arguments: test.arguments})
			if err != nil {
				t.Fatal(err)
			}
			if action.Operation != test.operation {
				t.Fatalf("operation = %q, want %q", action.Operation, test.operation)
			}
		})
	}
}

func TestActionKeepsURLCredentialsOutOfPrimaryResource(t *testing.T) {
	action, err := Action(Request{
		AgentID: "test", Tool: "http.request",
		Arguments: map[string]any{"url": "https://alice:secret@example.test/export?token=value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if action.Resource != "example.test" {
		t.Fatalf("resource = %q, want hostname only", action.Resource)
	}
}

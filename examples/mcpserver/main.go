// mcpserver is a side-effect-free MCP stdio server for exercising Latch.
package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 4<<20)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var incoming request
		if json.Unmarshal(scanner.Bytes(), &incoming) != nil {
			continue
		}
		switch incoming.Method {
		case "initialize":
			writeResult(encoder, incoming.ID, map[string]any{
				"protocolVersion": "2025-11-25",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "latch-demo-server", "version": "1.0.0"},
			})
		case "notifications/initialized":
			// Notifications do not receive responses.
		case "ping":
			writeResult(encoder, incoming.ID, map[string]any{})
		case "tools/list":
			writeResult(encoder, incoming.ID, map[string]any{"tools": demoTools()})
		case "tools/call":
			var params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if json.Unmarshal(incoming.Params, &params) != nil {
				writeError(encoder, incoming.ID, -32602, "invalid tool parameters")
				continue
			}
			writeResult(encoder, incoming.ID, map[string]any{
				"content": []any{map[string]any{
					"type": "text",
					"text": "Demo server received " + params.Name + "; no side effect was performed.",
				}},
			})
		default:
			if len(incoming.ID) > 0 {
				writeError(encoder, incoming.ID, -32601, "method not found")
			}
		}
	}
}

func demoTools() []any {
	return []any{
		map[string]any{
			"name":        "filesystem.read",
			"description": "Simulate reading a file without touching the filesystem.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
				"required":   []string{"path"},
			},
			"annotations": map[string]any{"readOnlyHint": true},
		},
		map[string]any{
			"name":        "shell.exec",
			"description": "Simulate a shell request without executing it.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"command": map[string]any{"type": "string"}},
				"required":   []string{"command"},
			},
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true},
		},
	}
}

func writeResult(encoder *json.Encoder, id json.RawMessage, result any) {
	_ = encoder.Encode(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result"`
	}{JSONRPC: "2.0", ID: id, Result: result})
}

func writeError(encoder *json.Encoder, id json.RawMessage, code int, message string) {
	_ = encoder.Encode(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   map[string]any  `json:"error"`
	}{JSONRPC: "2.0", ID: id, Error: map[string]any{"code": code, "message": message}})
}

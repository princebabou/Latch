// Package normalize converts tool-shaped requests into Latch's Action model.
package normalize

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/princebabou/Latch/pkg/models"
)

// Request is intentionally small: MCP adapters can map their tool call into it,
// while other integrations can construct an Action directly.
type Request struct {
	AgentID   string
	Tool      string
	Arguments map[string]any
	Metadata  map[string]any
}

// Action infers a generic operation and primary resource without discarding the
// original, protocol-specific arguments.
func Action(req Request) (models.Action, error) {
	tool := strings.TrimSpace(req.Tool)
	if tool == "" {
		return models.Action{}, fmt.Errorf("tool is required")
	}
	args := req.Arguments
	if args == nil {
		args = map[string]any{}
	}

	action := models.Action{
		AgentID: req.AgentID, Tool: tool, Operation: operationFor(tool, args),
		Arguments: args, Metadata: req.Metadata,
	}
	action.Resource = resourceFor(tool, args)
	return action, nil
}

func operationFor(tool string, arguments map[string]any) string {
	if explicit := normalizedOperation(stringValue(arguments, "operation", "action")); explicit != "" {
		return explicit
	}
	if _, ok := lookupValue(arguments, "command", "cmd", "script", "executable", "program"); ok {
		return "execute"
	}
	if _, ok := lookupValue(arguments, "query", "sql", "statement"); ok {
		return "query"
	}
	if _, ok := lookupValue(arguments, "url", "endpoint", "uri", "request_url", "base_url"); ok {
		return "network"
	}

	lower := strings.ToLower(tool)
	switch {
	case strings.Contains(lower, "read"):
		return "read"
	case strings.Contains(lower, "write"), strings.Contains(lower, "update"), strings.Contains(lower, "create"):
		return "write"
	case strings.Contains(lower, "delete"), strings.Contains(lower, "remove"):
		return "delete"
	case strings.Contains(lower, "exec"), strings.Contains(lower, "shell"), strings.Contains(lower, "command"):
		return "execute"
	case strings.Contains(lower, "query"):
		return "query"
	case strings.Contains(lower, "request"), strings.Contains(lower, "fetch"), strings.Contains(lower, "http"):
		return "network"
	default:
		return "invoke"
	}
}

func resourceFor(tool string, args map[string]any) string {
	for _, key := range []string{"path", "file", "filename", "url", "endpoint", "host", "table", "database", "command", "query"} {
		if value, ok := lookupValue(args, key); ok {
			if s, ok := value.(string); ok {
				if key == "url" || key == "endpoint" {
					if parsed, err := url.Parse(s); err == nil && parsed.Host != "" {
						return parsed.Host
					}
				}
				return s
			}
		}
	}
	return ""
}

func normalizedOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "read", "get", "list", "search":
		return "read"
	case "write", "update", "create", "put", "patch", "insert":
		return "write"
	case "delete", "remove", "drop", "truncate":
		return "delete"
	case "execute", "exec", "run", "shell":
		return "execute"
	case "query", "select", "sql":
		return "query"
	case "network", "request", "fetch", "http":
		return "network"
	default:
		return ""
	}
}

func stringValue(arguments map[string]any, keys ...string) string {
	value, ok := lookupValue(arguments, keys...)
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

func lookupValue(arguments map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := arguments[key]; ok {
			return value, true
		}
	}
	for existingKey, value := range arguments {
		for _, key := range keys {
			if strings.EqualFold(existingKey, key) {
				return value, true
			}
		}
	}
	return nil, false
}

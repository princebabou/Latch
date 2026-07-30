// Package audit writes redacted, structured enforcement records.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/princebabou/Latch/pkg/models"
)

var secretKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key)`)
var bearerValue = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]+`)
var inlineSecret = regexp.MustCompile(`(?i)((?:token|secret|api[_-]?key|password|passwd|authorization)=)[^\s&]+`)
var secretFlag = regexp.MustCompile(`(?i)(^|\s)((?:--?[a-z0-9_-]*(?:password|passwd|secret|token|api[_-]?key|credential|auth|bearer)[a-z0-9_-]*|-u)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)`)
var attachedUserFlag = regexp.MustCompile(`(?i)(^|\s)-u[^\s]+`)
var sensitiveHeaderFlag = regexp.MustCompile(`(?i)(^|\s)((?:-H|--header)(?:=|\s+)?)(?:"[^"]*(?:authorization|cookie|x-api-key)[^"]*"|'[^']*(?:authorization|cookie|x-api-key)[^']*'|[^\s]*(?:authorization|cookie|x-api-key)[^\s]*)`)
var urlUserInfo = regexp.MustCompile(`(?i)(https?://)[^/@\s]+@`)
var sqlSecretAssignment = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|credential)\b(\s*=\s*)(?:'(?:''|[^'])*'|"(?:\\"|[^"])*"|[^\s,;)]+)`)
var jsonLikeSecret = regexp.MustCompile(`(?i)(["']?(?:password|passwd|secret|token|api[_-]?key|authorization|credential)["']?\s*:\s*["'])(?:\\.|[^"'])*`)

// Logger is a minimal sink abstraction. SIEM and OpenTelemetry adapters can
// implement the same Write method later.
type Logger interface{ Write(models.AuditEvent) error }

type JSONLLogger struct{ Path string }

func (l JSONLLogger) Write(event models.AuditEvent) error {
	event.Timestamp = event.Timestamp.UTC()
	event.Action = RedactAction(event.Action)
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

func NewEvent(action models.Action, assessment models.Assessment, approval string) models.AuditEvent {
	return models.AuditEvent{Timestamp: time.Now().UTC(), Action: action, Assessment: assessment, Approval: approval}
}

// RedactAction removes common secret-bearing argument values before any event
// is serialized. It preserves keys and non-sensitive context for investigations.
func RedactAction(action models.Action) models.Action {
	copy := action
	copy.Resource = redactText(action.Resource)
	copy.Arguments = redactMap(action.Arguments)
	copy.Metadata = redactMap(action.Metadata)
	return copy
}

func redactMap(values map[string]any) map[string]any {
	return redactMapDepth(values, 0)
}

func redactMapDepth(values map[string]any, depth int) map[string]any {
	if values == nil {
		return nil
	}
	copy := make(map[string]any, len(values))
	for key, value := range values {
		if secretKey.MatchString(key) {
			copy[key] = "[REDACTED]"
			continue
		}
		copy[key] = redactValue(value, depth+1)
	}
	return copy
}

func redactText(value string) string {
	value = bearerValue.ReplaceAllString(value, "$1 [REDACTED]")
	value = inlineSecret.ReplaceAllString(value, "$1[REDACTED]")
	value = secretFlag.ReplaceAllString(value, "$1$2[REDACTED]")
	value = attachedUserFlag.ReplaceAllString(value, "$1-u[REDACTED]")
	value = sensitiveHeaderFlag.ReplaceAllString(value, "$1$2[REDACTED]")
	value = urlUserInfo.ReplaceAllString(value, "$1[REDACTED]@")
	value = sqlSecretAssignment.ReplaceAllString(value, "$1$2[REDACTED]")
	value = jsonLikeSecret.ReplaceAllString(value, "$1[REDACTED]")
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid([]byte(trimmed)) {
		var structured any
		if json.Unmarshal([]byte(trimmed), &structured) == nil {
			if encoded, err := json.Marshal(redactValue(structured, 0)); err == nil {
				return string(encoded)
			}
		}
	}
	return value
}

func redactValue(value any, depth int) any {
	if depth > 16 {
		return "[REDACTED:DEPTH_LIMIT]"
	}
	switch typed := value.(type) {
	case string:
		return redactText(typed)
	case []byte:
		return redactText(string(typed))
	case map[string]any:
		return redactMapDepth(typed, depth)
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for key, nested := range typed {
			converted[key] = nested
		}
		return redactMapDepth(converted, depth)
	case []any:
		copy := make([]any, len(typed))
		for index, nested := range typed {
			copy[index] = redactValue(nested, depth+1)
		}
		return copy
	case []string:
		copy := make([]any, len(typed))
		for index, nested := range typed {
			copy[index] = redactText(nested)
		}
		return copy
	}

	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return nil
	}
	switch reflected.Kind() {
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return value
		}
		converted := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			converted[iterator.Key().String()] = iterator.Value().Interface()
		}
		return redactMapDepth(converted, depth)
	case reflect.Slice, reflect.Array:
		copy := make([]any, reflected.Len())
		for index := 0; index < reflected.Len(); index++ {
			copy[index] = redactValue(reflected.Index(index).Interface(), depth+1)
		}
		return copy
	default:
		return value
	}
}

// Terminal renders an operator-friendly single-line record without leaking
// arguments, which may contain user data or secrets.
func Terminal(event models.AuditEvent) string {
	agentID := event.Assessment.CanonicalAgentID
	if agentID == "" {
		agentID = event.Action.AgentID
	}
	line := fmt.Sprintf(
		"LATCH %-16s risk=%3d source=%s agent=%s verified=%t tool=%s resource=%s",
		event.Assessment.Decision,
		event.Assessment.RiskScore,
		event.Assessment.DecisionSource,
		agentID,
		event.Assessment.IdentityVerified,
		event.Action.Tool,
		safeResource(event.Action.Resource),
	)
	if len(event.Assessment.Budgets) > 0 {
		parts := make([]string, 0, len(event.Assessment.Budgets))
		for _, status := range event.Assessment.Budgets {
			parts = append(parts, fmt.Sprintf("%s:%d/%d", status.RuleID, status.Used, status.Limit))
		}
		line += " budgets=" + strings.Join(parts, ",")
	}
	return line
}

func safeResource(resource string) string {
	resource = redactText(resource)
	if len(resource) > 180 {
		return resource[:177] + "..."
	}
	return strings.TrimSpace(resource)
}

// Package audit writes redacted, structured enforcement records.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/latch-security/latch/pkg/models"
)

var secretKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key)`)
var bearerValue = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]+`)
var inlineSecret = regexp.MustCompile(`(?i)((?:token|secret|api[_-]?key|password|passwd|authorization)=)[^\s&]+`)

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
	if values == nil {
		return nil
	}
	copy := make(map[string]any, len(values))
	for key, value := range values {
		if secretKey.MatchString(key) {
			copy[key] = "[REDACTED]"
			continue
		}
		switch typed := value.(type) {
		case string:
			copy[key] = redactText(typed)
		case map[string]any:
			copy[key] = redactMap(typed)
		default:
			copy[key] = value
		}
	}
	return copy
}

func redactText(value string) string {
	value = bearerValue.ReplaceAllString(value, "$1 [REDACTED]")
	return inlineSecret.ReplaceAllString(value, "$1[REDACTED]")
}

// Terminal renders an operator-friendly single-line record without leaking
// arguments, which may contain user data or secrets.
func Terminal(event models.AuditEvent) string {
	return fmt.Sprintf("LATCH %-16s risk=%3d tool=%s resource=%s", event.Assessment.Decision, event.Assessment.RiskScore, event.Action.Tool, safeResource(event.Action.Resource))
}

func safeResource(resource string) string {
	resource = redactText(resource)
	if len(resource) > 180 {
		return resource[:177] + "..."
	}
	return strings.TrimSpace(resource)
}

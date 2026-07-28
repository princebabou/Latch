package audit

import (
	"testing"

	"github.com/latch-security/latch/pkg/models"
)

func TestRedactAction(t *testing.T) {
	action := models.Action{Resource: "https://example.test?token=secret", Arguments: map[string]any{"api_key": "shh", "command": "curl https://x?token=secret", "normal": "safe"}}
	redacted := RedactAction(action)
	if redacted.Arguments["api_key"] != "[REDACTED]" {
		t.Fatalf("api key not redacted: %#v", redacted.Arguments["api_key"])
	}
	if redacted.Resource == action.Resource {
		t.Fatal("resource secret was not redacted")
	}
	if redacted.Arguments["normal"] != "safe" {
		t.Fatal("normal field changed")
	}
}

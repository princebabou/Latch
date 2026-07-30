package audit

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/princebabou/Latch/pkg/models"
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

func TestRedactActionHandlesStructuredHTTPBodiesAndTypedHeaders(t *testing.T) {
	action := models.Action{Arguments: map[string]any{
		"body": `{"profile":{"refresh_token":"body-secret"},"items":[{"password":"array-secret"}]}`,
		"headers": http.Header{
			"Authorization": {"Bearer header-secret"},
			"X-Normal":      {"safe"},
		},
	}}
	redacted := RedactAction(action)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, secret := range []string{"body-secret", "array-secret", "header-secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("redacted action leaked %q: %s", secret, output)
		}
	}
	if !strings.Contains(output, "safe") {
		t.Fatalf("ordinary header was lost: %s", output)
	}
}

func TestRedactActionHandlesShellCredentialForms(t *testing.T) {
	action := models.Action{
		Resource: `curl -u alice:secret -H "Cookie: sid=cookie-secret" https://bob:password@example.test/export`,
		Arguments: map[string]any{
			"command": "curl -ualice:attached --oauth2-bearer super-secret https://bob:password@example.test/export",
		},
	}
	encoded, err := json.Marshal(RedactAction(action))
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, secret := range []string{"alice:secret", "attached", "super-secret", "cookie-secret", "bob:password"} {
		if strings.Contains(output, secret) {
			t.Fatalf("redacted action leaked %q: %s", secret, output)
		}
	}
}

func TestRedactActionHandlesSQLAssignmentsAndMalformedJSON(t *testing.T) {
	action := models.Action{
		Resource: "UPDATE users SET password = 'sql-secret' WHERE id = 1",
		Arguments: map[string]any{
			"query": "UPDATE users SET api_key='key-secret' WHERE id = 1",
			"body":  `{"token":"json-secret"`,
		},
	}
	encoded, err := json.Marshal(RedactAction(action))
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, secret := range []string{"sql-secret", "key-secret", "json-secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("redacted action leaked %q: %s", secret, output)
		}
	}
}

func TestTerminalIncludesBudgetUsageWithoutArguments(t *testing.T) {
	event := models.AuditEvent{
		Action: models.Action{
			AgentID: "reader",
			Tool:    "filesystem.read",
			Arguments: map[string]any{
				"token": "must-not-appear",
			},
		},
		Assessment: models.Assessment{
			Decision:         models.DecisionAllow,
			DecisionSource:   "default_allow",
			CanonicalAgentID: "reader",
			Budgets: []models.BudgetStatus{{
				RuleID: "read-burst",
				Used:   3,
				Limit:  10,
			}},
		},
	}
	line := Terminal(event)
	if !strings.Contains(line, "budgets=read-burst:3/10") {
		t.Fatalf("terminal event = %q", line)
	}
	if strings.Contains(line, "must-not-appear") {
		t.Fatalf("terminal event leaked arguments: %q", line)
	}
}

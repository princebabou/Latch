package approvalnotify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

func TestNewReturnsNilWhenUnconfigured(t *testing.T) {
	notifier, err := New(policy.ApprovalNotify{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if notifier != nil {
		t.Fatal("expected nil notifier when no webhook is configured")
	}
	// A nil notifier must be safe to call.
	if err := notifier.Notify(context.Background(), Notification{}); err != nil {
		t.Fatalf("nil notify: %v", err)
	}
}

func TestGenericNotificationRedactsAndPosts(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := New(policy.ApprovalNotify{WebhookURL: server.URL, Format: "generic"})
	if err != nil {
		t.Fatal(err)
	}
	action := models.Action{
		AgentID: "deploy-agent", Tool: "shell.exec", Operation: "execute",
		Resource: "token=SUPERSECRETVALUE", Arguments: map[string]any{"command": "rm -rf /prod"},
	}
	assessment := models.Assessment{Decision: models.DecisionRequireApproval, RiskScore: 55, RiskLevel: "HIGH", DecisionSource: "policy_approval"}
	notification := FromResult(action, assessment, "fingerprint123")
	if strings.Contains(notification.Resource, "SUPERSECRETVALUE") {
		t.Fatalf("resource was not redacted: %q", notification.Resource)
	}
	if err := notifier.Notify(context.Background(), notification); err != nil {
		t.Fatalf("notify: %v", err)
	}
	approval, ok := received["approval"].(map[string]any)
	if !ok || approval["fingerprint"] != "fingerprint123" || approval["tool"] != "shell.exec" {
		t.Fatalf("unexpected payload: %#v", received)
	}
}

func TestSlackNotificationSendsText(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := New(policy.ApprovalNotify{WebhookURL: server.URL, Format: "slack"})
	if err != nil {
		t.Fatal(err)
	}
	notification := Notification{Tool: "shell.exec", RiskLevel: "HIGH", RiskScore: 55, Fingerprint: "abc123"}
	if err := notifier.Notify(context.Background(), notification); err != nil {
		t.Fatalf("notify: %v", err)
	}
	text, ok := payload["text"].(string)
	if !ok || !strings.Contains(text, "abc123") || !strings.Contains(text, "shell.exec") {
		t.Fatalf("unexpected slack payload: %#v", payload)
	}
}

func TestNotifyReportsWebhookFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier, err := New(policy.ApprovalNotify{WebhookURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := notifier.Notify(context.Background(), Notification{Tool: "x"}); err == nil {
		t.Fatal("expected an error when the webhook returns a non-2xx status")
	}
}

func TestNotifierRefusesRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/steal", http.StatusFound)
	}))
	defer server.Close()

	notifier, err := New(policy.ApprovalNotify{WebhookURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	// A redirect is not followed; the 302 is surfaced as a non-2xx failure
	// rather than delivering the notification to another host.
	if err := notifier.Notify(context.Background(), Notification{Tool: "x"}); err == nil {
		t.Fatal("expected redirect to be refused")
	}
}

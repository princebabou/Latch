// Package approvalnotify delivers out-of-band alerts when an action is held
// for human approval. Notification is always best-effort: a delivery failure
// never changes or weakens a verdict, and the action stays pending regardless.
package approvalnotify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	defaultTimeout   = 3 * time.Second
	maxResponseBytes = 64 << 10
	userAgent        = "latch-approval-notify/0.2"
)

// Notification is the redacted, audit-safe summary of a pending action.
type Notification struct {
	AgentID        string   `json:"agent_id,omitempty"`
	Tool           string   `json:"tool"`
	Operation      string   `json:"operation,omitempty"`
	Resource       string   `json:"resource,omitempty"`
	RiskScore      int      `json:"risk_score"`
	RiskLevel      string   `json:"risk_level,omitempty"`
	Fingerprint    string   `json:"fingerprint"`
	DecisionSource string   `json:"decision_source,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
}

// Notifier posts pending-approval notifications to a configured webhook. It is
// safe to share across goroutines.
type Notifier struct {
	endpoint   *url.URL
	format     string
	httpClient *http.Client
}

// Option customizes a Notifier, primarily for tests.
type Option func(*Notifier)

// WithHTTPClient injects transport. Redirects are always refused so a webhook
// cannot bounce the notification (and any host-derived trust) elsewhere.
func WithHTTPClient(client *http.Client) Option {
	return func(n *Notifier) {
		if client != nil {
			clone := *client
			clone.CheckRedirect = refuseRedirect
			n.httpClient = &clone
		}
	}
}

// New builds a Notifier from approval notification configuration. It returns a
// nil Notifier (and nil error) when no webhook is configured, so callers can
// unconditionally construct and nil-check.
func New(config policy.ApprovalNotify, options ...Option) (*Notifier, error) {
	raw := strings.TrimSpace(config.WebhookURL)
	if raw == "" {
		return nil, nil
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return nil, fmt.Errorf("approval webhook must be an absolute HTTP or HTTPS URL")
	}
	timeout := config.Timeout.Value()
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	format := strings.ToLower(strings.TrimSpace(config.Format))
	if format == "" {
		format = "generic"
	}
	notifier := &Notifier{
		endpoint: endpoint, format: format,
		httpClient: &http.Client{Timeout: timeout, CheckRedirect: refuseRedirect},
	}
	for _, option := range options {
		option(notifier)
	}
	return notifier, nil
}

// FromResult builds a redacted Notification from an evaluated action and its
// assessment. Resource text is passed through the audit redactor.
func FromResult(action models.Action, assessment models.Assessment, fingerprint string) Notification {
	safe := audit.RedactAction(action)
	return Notification{
		AgentID: action.AgentID, Tool: action.Tool, Operation: action.Operation,
		Resource: safe.Resource, RiskScore: assessment.RiskScore, RiskLevel: assessment.RiskLevel,
		Fingerprint: fingerprint, DecisionSource: assessment.DecisionSource, Reasons: assessment.Reasons,
	}
}

// Notify delivers one notification. Any transport or status error is returned
// for logging; callers must not treat it as an enforcement result.
func (n *Notifier) Notify(ctx context.Context, notification Notification) error {
	if n == nil {
		return nil
	}
	payload, err := n.encode(notification)
	if err != nil {
		return fmt.Errorf("encode approval notification: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create approval notification: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", userAgent)
	response, err := n.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("deliver approval notification: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("approval webhook returned status %d", response.StatusCode)
	}
	return nil
}

func (n *Notifier) encode(notification Notification) ([]byte, error) {
	if n.format == "slack" {
		return json.Marshal(map[string]string{"text": slackText(notification)})
	}
	return json.Marshal(struct {
		Type string       `json:"type"`
		Sent string       `json:"sent,omitempty"`
		Data Notification `json:"approval"`
	}{Type: "latch.approval.pending", Data: notification})
}

func slackText(notification Notification) string {
	var builder strings.Builder
	builder.WriteString("Latch approval required\n")
	fmt.Fprintf(&builder, "• tool: %s\n", notification.Tool)
	if notification.Operation != "" {
		fmt.Fprintf(&builder, "• operation: %s\n", notification.Operation)
	}
	if notification.AgentID != "" {
		fmt.Fprintf(&builder, "• agent: %s\n", notification.AgentID)
	}
	if notification.Resource != "" {
		fmt.Fprintf(&builder, "• resource: %s\n", notification.Resource)
	}
	fmt.Fprintf(&builder, "• risk: %s (%d)\n", notification.RiskLevel, notification.RiskScore)
	fmt.Fprintf(&builder, "• fingerprint: %s", notification.Fingerprint)
	return builder.String()
}

func refuseRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

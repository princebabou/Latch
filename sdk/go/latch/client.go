// Package latch is the official Go client for the Latch Enforcement API.
package latch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	defaultTimeout          = 2 * time.Second
	defaultMaxResponseBytes = 1 << 20
)

// Client makes fail-closed decisions against one Latch API instance.
type Client struct {
	endpoint         *url.URL
	token            string
	httpClient       *http.Client
	maxResponseBytes int64
}

type Option func(*Client) error

// WithToken authenticates requests without placing the token in the URL.
func WithToken(token string) Option {
	return func(client *Client) error {
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf("token cannot be empty")
		}
		client.token = token
		return nil
	}
}

// WithHTTPClient supplies transport settings. Redirects are still disabled so
// bearer credentials and decisions cannot move to another endpoint.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(client *Client) error {
		if httpClient == nil {
			return fmt.Errorf("HTTP client cannot be nil")
		}
		clone := *httpClient
		if clone.Timeout <= 0 {
			clone.Timeout = client.httpClient.Timeout
		}
		clone.CheckRedirect = refuseRedirect
		client.httpClient = &clone
		return nil
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(client *Client) error {
		if timeout <= 0 {
			return fmt.Errorf("timeout must be positive")
		}
		client.httpClient.Timeout = timeout
		return nil
	}
}

func WithMaxResponseBytes(limit int64) Option {
	return func(client *Client) error {
		if limit < 1024 || limit > 16<<20 {
			return fmt.Errorf("response limit must be between 1024 and 16777216 bytes")
		}
		client.maxResponseBytes = limit
		return nil
	}
}

// New creates a client from a Latch server base URL, for example
// http://127.0.0.1:7070. Embedded credentials, query strings, and fragments are
// rejected.
func New(baseURL string, options ...Option) (*Client, error) {
	endpoint, err := decisionEndpoint(baseURL)
	if err != nil {
		return nil, err
	}
	client := &Client{
		endpoint: endpoint, maxResponseBytes: defaultMaxResponseBytes,
		httpClient: &http.Client{Timeout: defaultTimeout, CheckRedirect: refuseRedirect},
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("client option cannot be nil")
		}
		if err := option(client); err != nil {
			return nil, err
		}
	}
	return client, nil
}

// Decide submits one intended action. Any transport, HTTP, or protocol error
// is returned as an error and must be treated as a denial by callers.
func (client *Client) Decide(ctx context.Context, action api.Action) (api.DecisionResponse, error) {
	requestID, err := api.NewRequestID()
	if err != nil {
		return api.DecisionResponse{}, &UnavailableError{Cause: err}
	}
	requestBody := api.DecisionRequest{APIVersion: api.APIVersion, RequestID: requestID, Action: action}
	if err := requestBody.Validate(); err != nil {
		return api.DecisionResponse{}, fmt.Errorf("invalid action: %w", err)
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return api.DecisionResponse{}, fmt.Errorf("encode decision request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return api.DecisionResponse{}, fmt.Errorf("create decision request: %w", err)
	}
	request.Header.Set("Accept", api.MediaType)
	request.Header.Set("Content-Type", api.MediaType)
	request.Header.Set("User-Agent", "latch-go/0.2")
	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return api.DecisionResponse{}, &UnavailableError{Cause: err}
	}
	defer response.Body.Close()
	payload, err := readBounded(response.Body, client.maxResponseBytes)
	if err != nil {
		return api.DecisionResponse{}, &ProtocolError{Message: err.Error()}
	}
	if response.StatusCode != http.StatusOK {
		return api.DecisionResponse{}, decodeAPIError(response.StatusCode, payload)
	}
	if err := validateMediaType(response.Header.Get("Content-Type")); err != nil {
		return api.DecisionResponse{}, &ProtocolError{Message: err.Error()}
	}
	var decision api.DecisionResponse
	if err := json.Unmarshal(payload, &decision); err != nil {
		return api.DecisionResponse{}, &ProtocolError{Message: "response is not valid decision JSON"}
	}
	if err := validateResponseShape(payload); err != nil {
		return api.DecisionResponse{}, &ProtocolError{Message: err.Error()}
	}
	if err := validateDecision(decision, requestID); err != nil {
		return api.DecisionResponse{}, &ProtocolError{Message: err.Error()}
	}
	return decision, nil
}

// Guard calls execute only after an explicit, valid ALLOW. It is the safest
// integration path for short tool wrappers.
func (client *Client) Guard(ctx context.Context, action api.Action, execute func(context.Context) error) (api.DecisionResponse, error) {
	if execute == nil {
		return api.DecisionResponse{}, fmt.Errorf("execute function cannot be nil")
	}
	result, err := client.Decide(ctx, action)
	if err != nil {
		return api.DecisionResponse{}, err
	}
	if result.Decision != models.DecisionAllow {
		return result, &NotAllowedError{Response: result}
	}
	if err := execute(ctx); err != nil {
		return result, fmt.Errorf("execute allowed action: %w", err)
	}
	return result, nil
}

type UnavailableError struct{ Cause error }

func (err *UnavailableError) Error() string {
	return "Latch is unavailable; action not executed: " + err.Cause.Error()
}
func (err *UnavailableError) Unwrap() error { return err.Cause }

type ProtocolError struct{ Message string }

func (err *ProtocolError) Error() string {
	return "invalid Latch response; action not executed: " + err.Message
}

type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (err *APIError) Error() string {
	return fmt.Sprintf("Latch API rejected the request (%d %s): %s", err.StatusCode, err.Code, err.Message)
}

type NotAllowedError struct{ Response api.DecisionResponse }

func (err *NotAllowedError) Error() string {
	return fmt.Sprintf("Latch decision is %s; action not executed", err.Response.Decision)
}

func decisionEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("base URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("base URL cannot contain credentials, a query, or a fragment")
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if path == "" {
		path = "/v1/decisions"
	} else if path != "/v1/decisions" {
		return nil, fmt.Errorf("base URL path must be empty or /v1/decisions")
	}
	parsed.Path = path
	parsed.RawPath = ""
	return parsed, nil
}

func refuseRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return payload, nil
}

func validateMediaType(header string) error {
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil || (mediaType != api.MediaType && mediaType != "application/json") {
		return fmt.Errorf("unexpected response content type")
	}
	return nil
}

func validateDecision(decision api.DecisionResponse, requestID string) error {
	if decision.APIVersion != api.APIVersion {
		return fmt.Errorf("unsupported api_version %q", decision.APIVersion)
	}
	if decision.RequestID != requestID {
		return fmt.Errorf("response request_id does not match the request")
	}
	switch decision.Decision {
	case models.DecisionAllow, models.DecisionBlock, models.DecisionRequireApproval:
	default:
		return fmt.Errorf("unknown decision %q", decision.Decision)
	}
	if strings.TrimSpace(decision.Policy.DecisionSource) == "" {
		return fmt.Errorf("decision_source is missing")
	}
	if decision.Risk.Score < 0 || decision.Risk.Score > 100 || strings.TrimSpace(decision.Risk.Level) == "" {
		return fmt.Errorf("risk evidence is invalid")
	}
	if decision.Decision == models.DecisionAllow && decision.FailClosed {
		return fmt.Errorf("fail_closed response cannot allow execution")
	}
	return nil
}

func validateResponseShape(payload []byte) error {
	var root map[string]json.RawMessage
	if json.Unmarshal(payload, &root) != nil || root == nil {
		return fmt.Errorf("decision response must be a JSON object")
	}
	for _, field := range []string{"api_version", "request_id", "decision", "risk", "identity", "policy"} {
		if _, exists := root[field]; !exists {
			return fmt.Errorf("required response field %q is missing", field)
		}
	}
	for name, fields := range map[string][]string{
		"risk": {"score", "level"}, "identity": {"verified"}, "policy": {"decision_source", "hard_deny"},
	} {
		var nested map[string]json.RawMessage
		if json.Unmarshal(root[name], &nested) != nil || nested == nil {
			return fmt.Errorf("response field %q must be an object", name)
		}
		for _, field := range fields {
			if _, exists := nested[field]; !exists {
				return fmt.Errorf("required response field %q.%s is missing", name, field)
			}
		}
	}
	return nil
}

func decodeAPIError(status int, payload []byte) error {
	var response api.ErrorResponse
	if json.Unmarshal(payload, &response) == nil && response.APIVersion == api.APIVersion && response.Error.Code != "" {
		return &APIError{StatusCode: status, Code: response.Error.Code, Message: response.Error.Message}
	}
	return &APIError{StatusCode: status, Code: "http_error", Message: http.StatusText(status)}
}

func IsNotAllowed(err error) bool {
	var target *NotAllowedError
	return errors.As(err, &target)
}

// Package enforcementapi exposes the stable versioned Latch decision contract.
package enforcementapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/approval"
	"github.com/princebabou/Latch/internal/approvalnotify"
	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/normalize"
	"github.com/princebabou/Latch/internal/strictjson"
	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	defaultMaxBodyBytes = 1 << 20
	defaultReplayWindow = 10 * time.Minute
	defaultReplayLimit  = 10_000
)

// Options configures the v1 HTTP API. AgentID is an operator-established
// identity binding; request body identity claims remain unverified without it.
type Options struct {
	Service        *decision.Service
	AgentID        string
	BearerToken    string
	ApproverToken  string
	Notifier       *approvalnotify.Notifier
	AllowedOrigins []string
	MaxBodyBytes   int64
	ReplayWindow   time.Duration
	ReplayLimit    int
	Diagnostics    io.Writer
	Now            func() time.Time
}

type Handler struct {
	service        *decision.Service
	agentID        string
	bearerHash     [sha256.Size]byte
	requireBearer  bool
	approverHash   [sha256.Size]byte
	requireApprove bool
	notifier       *approvalnotify.Notifier
	allowedOrigins map[string]struct{}
	maxBodyBytes   int64
	replay         *replayCache
	diagnostics    io.Writer
}

func New(options Options) (*Handler, error) {
	if options.Service == nil {
		return nil, fmt.Errorf("decision service is required")
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = defaultMaxBodyBytes
	}
	if options.MaxBodyBytes < 1024 || options.MaxBodyBytes > 16<<20 {
		return nil, fmt.Errorf("max body size must be between 1024 and 16777216 bytes")
	}
	if options.ReplayWindow <= 0 {
		options.ReplayWindow = defaultReplayWindow
	}
	if options.ReplayLimit <= 0 {
		options.ReplayLimit = defaultReplayLimit
	}
	if options.Diagnostics == nil {
		options.Diagnostics = io.Discard
	}
	origins := make(map[string]struct{}, len(options.AllowedOrigins))
	for _, origin := range options.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if !validOrigin(origin) {
			return nil, fmt.Errorf("allowed origin %q must be an explicit HTTP or HTTPS origin without a path", origin)
		}
		origins[origin] = struct{}{}
	}
	handler := &Handler{
		service: options.Service, agentID: strings.TrimSpace(options.AgentID),
		notifier: options.Notifier, allowedOrigins: origins, maxBodyBytes: options.MaxBodyBytes,
		replay:      newReplayCache(options.ReplayWindow, options.ReplayLimit, options.Now),
		diagnostics: options.Diagnostics,
	}
	if options.BearerToken != "" {
		if len(options.BearerToken) < 32 || len(options.BearerToken) > 4096 {
			return nil, fmt.Errorf("bearer token must contain between 32 and 4096 bytes")
		}
		handler.requireBearer = true
		handler.bearerHash = sha256.Sum256([]byte(options.BearerToken))
	}
	if options.ApproverToken != "" {
		if len(options.ApproverToken) < 32 || len(options.ApproverToken) > 4096 {
			return nil, fmt.Errorf("approver token must contain between 32 and 4096 bytes")
		}
		if options.ApproverToken == options.BearerToken {
			return nil, fmt.Errorf("approver token must differ from the decision bearer token")
		}
		handler.requireApprove = true
		handler.approverHash = sha256.Sum256([]byte(options.ApproverToken))
	}
	return handler, nil
}

func validOrigin(origin string) bool {
	if origin == "" || origin == "*" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return false
	}
	return parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	secureHeaders(response)
	switch request.URL.Path {
	case "/healthz", "/readyz":
		if request.Method != http.MethodGet {
			h.writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is supported", "")
			return
		}
		h.writeJSON(response, http.StatusOK, map[string]any{"api_version": api.APIVersion, "status": "ok"})
		return
	case "/v1/decisions":
	case "/v1/approvals":
		h.serveApprovals(response, request)
		return
	default:
		h.writeError(response, http.StatusNotFound, "not_found", "endpoint not found", "")
		return
	}

	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin != "" {
		if _, allowed := h.allowedOrigins[origin]; !allowed {
			h.writeError(response, http.StatusForbidden, "origin_forbidden", "origin is not allowed", "")
			return
		}
		response.Header().Set("Access-Control-Allow-Origin", origin)
		response.Header().Set("Vary", "Origin")
	}
	if request.Method == http.MethodOptions {
		response.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		response.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		response.Header().Set("Access-Control-Max-Age", "600")
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", "POST, OPTIONS")
		h.writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported", "")
		return
	}
	if !h.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="latch"`)
		h.writeError(response, http.StatusUnauthorized, "unauthorized", "valid bearer authentication is required", "")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != api.MediaType) {
		h.writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "use application/json or the Latch v1 media type", "")
		return
	}
	if request.ContentLength > h.maxBodyBytes {
		h.writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the configured limit", "")
		return
	}

	request.Body = http.MaxBytesReader(response, request.Body, h.maxBodyBytes)
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the configured limit", "")
			return
		}
		h.writeError(response, http.StatusBadRequest, "invalid_json", "request body could not be read safely", "")
		return
	}
	var input api.DecisionRequest
	if err := strictjson.DecodeDisallowUnknown(payload, &input); err != nil {
		h.writeError(response, http.StatusBadRequest, "invalid_json", "request body must be one valid JSON object using only v1 fields", "")
		return
	}
	if err := input.Validate(); err != nil {
		h.writeError(response, http.StatusBadRequest, "invalid_request", err.Error(), input.RequestID)
		return
	}
	switch h.replay.claim(input.RequestID) {
	case claimDuplicate:
		h.writeError(response, http.StatusConflict, "replayed_request", "request_id has already been used", input.RequestID)
		return
	case claimCapacity:
		response.Header().Set("Retry-After", "1")
		h.writeError(response, http.StatusServiceUnavailable, "replay_capacity_exhausted", "replay protection is temporarily at capacity", input.RequestID)
		return
	}

	metadata := cloneMap(input.Action.Metadata)
	metadata["protocol"] = "latch-enforcement-api"
	metadata["transport"] = "http"
	metadata["api_version"] = api.APIVersion
	metadata["request_id"] = input.RequestID
	action, err := normalize.Action(normalize.Request{
		AgentID: input.Action.AgentID, Tool: input.Action.Tool,
		Arguments: input.Action.Arguments, Metadata: metadata,
	})
	if err != nil {
		h.writeError(response, http.StatusBadRequest, "invalid_action", err.Error(), input.RequestID)
		return
	}
	if operation := strings.TrimSpace(input.Action.Operation); operation != "" {
		action.Operation = operation
	}
	if resource := strings.TrimSpace(input.Action.Resource); resource != "" {
		action.Resource = resource
	}
	identity := models.IdentityContext{ID: action.AgentID, Verified: false, Source: "api_request"}
	if h.agentID != "" {
		action.AgentID = h.agentID
		identity = models.IdentityContext{ID: h.agentID, Verified: true, Source: "api_server_config"}
	}
	result := h.service.Decide(action, identity)
	if diagnostic := decision.Diagnostic(result); diagnostic != "" {
		fmt.Fprintln(h.diagnostics, diagnostic)
	}
	if h.service.Policy.Audit.Terminal {
		fmt.Fprintln(h.diagnostics, audit.Terminal(result.Event))
	}
	decisionResponse := api.Response(input.RequestID, result.Assessment, result.OperationalError != nil)
	if result.Approval == "pending" {
		if fingerprint, err := approval.Fingerprint(result.Action); err == nil {
			decisionResponse.Approval = &api.ApprovalChallenge{Status: "pending", Fingerprint: fingerprint}
			h.notifyPending(request.Context(), result, fingerprint)
		}
	}
	h.writeJSON(response, http.StatusOK, decisionResponse)
}

// notifyPending fires a best-effort out-of-band alert. A delivery failure is
// logged to diagnostics and never affects the already-pending verdict.
func (h *Handler) notifyPending(ctx context.Context, result decision.Result, fingerprint string) {
	if h.notifier == nil {
		return
	}
	notification := approvalnotify.FromResult(result.Action, result.Assessment, fingerprint)
	if err := h.notifier.Notify(ctx, notification); err != nil {
		fmt.Fprintf(h.diagnostics, "Latch: approval notification failed: %v\n", err)
	}
}

func (h *Handler) authorized(header string) bool {
	if !h.requireBearer {
		return true
	}
	return matchesToken(header, h.bearerHash)
}

func (h *Handler) approverAuthorized(header string) bool {
	return matchesToken(header, h.approverHash)
}

func matchesToken(header string, expected [sha256.Size]byte) bool {
	scheme, token, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return false
	}
	actual := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

// approvalRequest issues a human grant for one exact pending action. The
// action is the same shape as a decision request so the approver names the
// action explicitly rather than trusting an opaque fingerprint.
type approvalRequest struct {
	APIVersion string     `json:"api_version"`
	Approver   string     `json:"approver"`
	TTLSeconds int        `json:"ttl_seconds,omitempty"`
	Action     api.Action `json:"action"`
}

// serveApprovals issues and lists human grants. It is enabled only when a
// dedicated approver token is configured, and that token is distinct from the
// decision bearer token so an agent can never approve its own held actions.
func (h *Handler) serveApprovals(response http.ResponseWriter, request *http.Request) {
	if !h.requireApprove {
		h.writeError(response, http.StatusNotFound, "not_found", "endpoint not found", "")
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		response.Header().Set("Allow", "GET, POST")
		h.writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "only GET and POST are supported", "")
		return
	}
	if !h.approverAuthorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="latch-approvals"`)
		h.writeError(response, http.StatusUnauthorized, "unauthorized", "valid approver authentication is required", "")
		return
	}
	if request.Method == http.MethodGet {
		grants, err := h.service.ApprovalStore.List()
		if err != nil {
			h.writeError(response, http.StatusServiceUnavailable, "approval_store_failure", "approval state could not be read", "")
			return
		}
		h.writeJSON(response, http.StatusOK, map[string]any{"api_version": api.APIVersion, "grants": grants})
		return
	}

	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != api.MediaType) {
		h.writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "use application/json or the Latch v1 media type", "")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, h.maxBodyBytes)
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		h.writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the configured limit", "")
		return
	}
	var input approvalRequest
	if err := strictjson.DecodeDisallowUnknown(payload, &input); err != nil {
		h.writeError(response, http.StatusBadRequest, "invalid_json", "request body must be one valid JSON object using only approval fields", "")
		return
	}
	if input.APIVersion != api.APIVersion {
		h.writeError(response, http.StatusBadRequest, "invalid_request", fmt.Sprintf("api_version must be %q", api.APIVersion), "")
		return
	}
	approver := strings.TrimSpace(input.Approver)
	if approver == "" || len(approver) > 256 {
		h.writeError(response, http.StatusBadRequest, "invalid_request", "approver identity is required", "")
		return
	}
	if input.TTLSeconds < 0 || input.TTLSeconds > 7*24*3600 {
		h.writeError(response, http.StatusBadRequest, "invalid_request", "ttl_seconds must be between 0 and 604800", "")
		return
	}
	action, err := h.normalizeApprovalAction(input.Action)
	if err != nil {
		h.writeError(response, http.StatusBadRequest, "invalid_action", err.Error(), "")
		return
	}
	ttl := time.Duration(input.TTLSeconds) * time.Second
	grant, err := h.service.ApprovalStore.Issue(action, "api:"+approver, ttl)
	if err != nil {
		h.writeError(response, http.StatusUnprocessableEntity, "approval_rejected", err.Error(), "")
		return
	}
	fmt.Fprintf(h.diagnostics, "Latch: approval %s issued for %s by api:%s\n", grant.ID, grant.Tool, approver)
	h.writeJSON(response, http.StatusCreated, map[string]any{
		"api_version": api.APIVersion,
		"grant": map[string]any{
			"id": grant.ID, "fingerprint": grant.Fingerprint, "approver": grant.Approver,
			"tool": grant.Tool, "expires_at": grant.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

func (h *Handler) normalizeApprovalAction(input api.Action) (models.Action, error) {
	metadata := cloneMap(input.Metadata)
	metadata["protocol"] = "latch-enforcement-api"
	metadata["transport"] = "http"
	metadata["surface"] = "approval"
	action, err := normalize.Action(normalize.Request{
		AgentID: input.AgentID, Tool: input.Tool, Arguments: input.Arguments, Metadata: metadata,
	})
	if err != nil {
		return models.Action{}, err
	}
	if operation := strings.TrimSpace(input.Operation); operation != "" {
		action.Operation = operation
	}
	if resource := strings.TrimSpace(input.Resource); resource != "" {
		action.Resource = resource
	}
	if h.agentID != "" {
		action.AgentID = h.agentID
	}
	return action, nil
}

func (h *Handler) writeError(response http.ResponseWriter, status int, code, message, requestID string) {
	h.writeJSON(response, status, api.ErrorResponse{APIVersion: api.APIVersion, RequestID: requestID, Error: api.Error{Code: code, Message: message}})
}

func (h *Handler) writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", api.MediaType)
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func cloneMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input)+4)
	for key, value := range input {
		output[key] = value
	}
	return output
}

func secureHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
}

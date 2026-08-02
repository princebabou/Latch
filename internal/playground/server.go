// Package playground exposes a local, execution-free policy simulation UI.
package playground

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/princebabou/Latch/internal/enforce"
	"github.com/princebabou/Latch/internal/normalize"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/internal/strictjson"
	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	SchemaVersion          = "latch.playground/v1"
	defaultMaxRequestBytes = 2 << 20
	maxPolicyBytes         = 256 << 10
	maxRules               = 1024
)

//go:embed static/index.html static/app.css static/app.js
var staticAssets embed.FS

type Options struct {
	PolicyYAML      string
	PolicyDirectory string
	AgentID         string
	MaxRequestBytes int64
	Token           string
}

type Handler struct {
	policyYAML      string
	policyDirectory string
	agentID         string
	maxRequestBytes int64
	token           string
	index           []byte
	stylesheet      []byte
	script          []byte
}

type IdentityInput struct {
	ID       string `json:"id"`
	Verified *bool  `json:"verified"`
}

type EvaluateRequest struct {
	PolicyYAML         string        `json:"policy_yaml"`
	BaselinePolicyYAML string        `json:"baseline_policy_yaml,omitempty"`
	Action             api.Action    `json:"action"`
	Identity           IdentityInput `json:"identity"`
}

type Evaluation struct {
	NormalizedAction models.Action     `json:"normalized_action"`
	Assessment       models.Assessment `json:"assessment"`
	MatchedRules     []RuleTrace       `json:"matched_rules"`
	Policy           PolicySummary     `json:"policy"`
}

type RuleTrace struct {
	ID          string          `json:"id"`
	Description string          `json:"description,omitempty"`
	Priority    int             `json:"priority"`
	Action      models.Decision `json:"action"`
}

type PolicySummary struct {
	Digest      string `json:"digest"`
	Rules       int    `json:"rules"`
	BudgetRules int    `json:"budget_rules"`
	Agents      int    `json:"agents"`
}

type DecisionDelta struct {
	Changed          bool            `json:"changed"`
	Weakened         bool            `json:"weakened"`
	From             models.Decision `json:"from"`
	To               models.Decision `json:"to"`
	RiskDelta        int             `json:"risk_delta"`
	AddedRules       []string        `json:"added_rules,omitempty"`
	RemovedRules     []string        `json:"removed_rules,omitempty"`
	SourceChanged    bool            `json:"source_changed"`
	IdentityChanged  bool            `json:"identity_changed"`
	PolicyWasChanged bool            `json:"policy_was_changed"`
}

type EvaluateResponse struct {
	SchemaVersion string         `json:"schema_version"`
	Mode          string         `json:"mode"`
	Evaluation    Evaluation     `json:"evaluation"`
	Baseline      *Evaluation    `json:"baseline,omitempty"`
	Delta         *DecisionDelta `json:"delta,omitempty"`
	Notices       []string       `json:"notices"`
}

type BootstrapResponse struct {
	SchemaVersion string     `json:"schema_version"`
	Mode          string     `json:"mode"`
	PolicyYAML    string     `json:"policy_yaml"`
	AgentID       string     `json:"agent_id"`
	Token         string     `json:"token"`
	MaxBytes      int64      `json:"max_request_bytes"`
	DefaultAction api.Action `json:"default_action"`
}

type errorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	Error         struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func New(options Options) (*Handler, error) {
	if strings.TrimSpace(options.PolicyYAML) == "" {
		return nil, fmt.Errorf("initial policy YAML is required")
	}
	if len(options.PolicyYAML) > maxPolicyBytes {
		return nil, fmt.Errorf("initial policy exceeds %d bytes", maxPolicyBytes)
	}
	config, err := policy.Parse([]byte(options.PolicyYAML), options.PolicyDirectory)
	if err != nil {
		return nil, fmt.Errorf("validate initial playground policy: %w", err)
	}
	if len(config.Rules) > maxRules {
		return nil, fmt.Errorf("initial policy exceeds %d rules", maxRules)
	}
	if options.MaxRequestBytes == 0 {
		options.MaxRequestBytes = defaultMaxRequestBytes
	}
	if options.MaxRequestBytes < 64<<10 || options.MaxRequestBytes > 4<<20 {
		return nil, fmt.Errorf("max request size must be between 65536 and 4194304 bytes")
	}
	if strings.TrimSpace(options.AgentID) == "" {
		options.AgentID = firstAgent(config)
	}
	if strings.TrimSpace(options.AgentID) == "" {
		options.AgentID = "playground-agent"
	}
	if options.Token == "" {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, fmt.Errorf("create playground session token: %w", err)
		}
		options.Token = hex.EncodeToString(raw[:])
	}
	index, err := staticAssets.ReadFile("static/index.html")
	if err != nil {
		return nil, err
	}
	stylesheet, err := staticAssets.ReadFile("static/app.css")
	if err != nil {
		return nil, err
	}
	script, err := staticAssets.ReadFile("static/app.js")
	if err != nil {
		return nil, err
	}
	return &Handler{
		policyYAML: options.PolicyYAML, policyDirectory: options.PolicyDirectory,
		agentID: strings.TrimSpace(options.AgentID), maxRequestBytes: options.MaxRequestBytes,
		token: options.Token, index: index, stylesheet: stylesheet, script: script,
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	secureHeaders(response)
	if !isLoopbackAuthority(request.Host) {
		handler.writeError(response, http.StatusMisdirectedRequest, "invalid_host", "the playground accepts only loopback hosts")
		return
	}
	switch request.URL.Path {
	case "/":
		handler.serveAsset(response, request, "text/html; charset=utf-8", handler.index)
	case "/app.css":
		handler.serveAsset(response, request, "text/css; charset=utf-8", handler.stylesheet)
	case "/app.js":
		handler.serveAsset(response, request, "text/javascript; charset=utf-8", handler.script)
	case "/api/bootstrap":
		handler.bootstrap(response, request)
	case "/api/evaluate":
		handler.evaluate(response, request)
	default:
		handler.writeError(response, http.StatusNotFound, "not_found", "route not found")
	}
}

func (handler *Handler) serveAsset(response http.ResponseWriter, request *http.Request, contentType string, payload []byte) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		handler.writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "only GET and HEAD are supported")
		return
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = response.Write(payload)
	}
}

func (handler *Handler) bootstrap(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", "GET")
		handler.writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is supported")
		return
	}
	handler.writeJSON(response, http.StatusOK, BootstrapResponse{
		SchemaVersion: SchemaVersion, Mode: "simulation", PolicyYAML: handler.policyYAML,
		AgentID: handler.agentID, Token: handler.token, MaxBytes: handler.maxRequestBytes,
		DefaultAction: api.Action{Tool: "filesystem.read", Arguments: map[string]any{"path": "./README.md"}},
	})
}

func (handler *Handler) evaluate(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", "POST")
		handler.writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}
	if !sameOrigin(request) {
		handler.writeError(response, http.StatusForbidden, "cross_origin", "cross-origin playground requests are forbidden")
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.Header.Get("X-Latch-Playground-Token")), []byte(handler.token)) != 1 {
		handler.writeError(response, http.StatusForbidden, "invalid_session", "the playground session token is missing or invalid")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		handler.writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "use application/json")
		return
	}
	if request.ContentLength > handler.maxRequestBytes {
		handler.writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", "playground request exceeds the configured limit")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, handler.maxRequestBytes)
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			handler.writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", "playground request exceeds the configured limit")
			return
		}
		handler.writeError(response, http.StatusBadRequest, "invalid_request", "request body could not be read safely")
		return
	}
	var input EvaluateRequest
	if err := strictjson.DecodeDisallowUnknown(payload, &input); err != nil {
		handler.writeError(response, http.StatusBadRequest, "invalid_json", "request must be one unambiguous JSON object using only playground v1 fields")
		return
	}
	if err := validateInput(input); err != nil {
		handler.writeError(response, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	evaluation, err := handler.run(input.PolicyYAML, input.Action, input.Identity)
	if err != nil {
		handler.writeError(response, http.StatusUnprocessableEntity, "evaluation_failed", err.Error())
		return
	}
	result := EvaluateResponse{
		SchemaVersion: SchemaVersion, Mode: "simulation", Evaluation: evaluation,
		Notices: []string{
			"No tool, command, network request, or upstream service was executed.",
			"Durable approvals and live budget usage are intentionally excluded from this isolated simulation.",
		},
	}
	if strings.TrimSpace(input.BaselinePolicyYAML) != "" {
		baseline, err := handler.run(input.BaselinePolicyYAML, input.Action, input.Identity)
		if err != nil {
			handler.writeError(response, http.StatusUnprocessableEntity, "baseline_failed", "baseline policy: "+err.Error())
			return
		}
		result.Baseline = &baseline
		delta := compareEvaluations(baseline, evaluation)
		result.Delta = &delta
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func validateInput(input EvaluateRequest) error {
	if strings.TrimSpace(input.PolicyYAML) == "" {
		return fmt.Errorf("policy_yaml is required")
	}
	if len(input.PolicyYAML) > maxPolicyBytes || len(input.BaselinePolicyYAML) > maxPolicyBytes {
		return fmt.Errorf("each policy document must not exceed %d bytes", maxPolicyBytes)
	}
	if input.Identity.Verified == nil {
		return fmt.Errorf("identity.verified is required")
	}
	if len(input.Identity.ID) > 256 {
		return fmt.Errorf("identity.id cannot exceed 256 bytes")
	}
	contract := api.DecisionRequest{APIVersion: api.APIVersion, RequestID: "req_playground", Action: input.Action}
	if err := contract.Validate(); err != nil {
		return err
	}
	return nil
}

func (handler *Handler) run(policyYAML string, actionInput api.Action, identityInput IdentityInput) (Evaluation, error) {
	config, err := policy.Parse([]byte(policyYAML), handler.policyDirectory)
	if err != nil {
		return Evaluation{}, err
	}
	if len(config.Rules) > maxRules {
		return Evaluation{}, fmt.Errorf("policy cannot contain more than %d rules", maxRules)
	}
	agentID := strings.TrimSpace(identityInput.ID)
	if agentID == "" {
		agentID = handler.agentID
	}
	actionAgentID := strings.TrimSpace(actionInput.AgentID)
	if actionAgentID == "" {
		actionAgentID = agentID
	}
	action, err := normalize.Action(normalize.Request{
		AgentID: actionAgentID, Tool: actionInput.Tool,
		Arguments: actionInput.Arguments, Metadata: actionInput.Metadata,
	})
	if err != nil {
		return Evaluation{}, err
	}
	if strings.TrimSpace(actionInput.Operation) != "" {
		action.Operation = strings.TrimSpace(actionInput.Operation)
	}
	if strings.TrimSpace(actionInput.Resource) != "" {
		action.Resource = strings.TrimSpace(actionInput.Resource)
	}
	identity := models.IdentityContext{ID: agentID, Verified: *identityInput.Verified, Source: "playground_input"}
	assessment := enforce.EvaluateWithIdentity(config, action, identity)
	matching := policy.Evaluate(config, action)
	rules := make([]RuleTrace, 0, len(matching.Rules))
	for _, rule := range matching.Rules {
		rules = append(rules, RuleTrace{ID: rule.ID, Description: rule.Description, Priority: rule.Priority, Action: rule.Action})
	}
	digest, err := policy.Digest(config)
	if err != nil {
		return Evaluation{}, err
	}
	return Evaluation{
		NormalizedAction: action, Assessment: assessment, MatchedRules: rules,
		Policy: PolicySummary{Digest: digest, Rules: len(config.Rules), BudgetRules: len(config.Budgets.Rules), Agents: len(config.Identity.Agents)},
	}, nil
}

func compareEvaluations(baseline, current Evaluation) DecisionDelta {
	added, removed := setDifference(ruleIDs(baseline.MatchedRules), ruleIDs(current.MatchedRules))
	delta := DecisionDelta{
		From: baseline.Assessment.Decision, To: current.Assessment.Decision,
		RiskDelta:  current.Assessment.RiskScore - baseline.Assessment.RiskScore,
		AddedRules: added, RemovedRules: removed,
		SourceChanged:    baseline.Assessment.DecisionSource != current.Assessment.DecisionSource,
		IdentityChanged:  baseline.Assessment.IdentityVerified != current.Assessment.IdentityVerified || baseline.Assessment.CanonicalAgentID != current.Assessment.CanonicalAgentID,
		PolicyWasChanged: baseline.Policy.Digest != current.Policy.Digest,
	}
	delta.Changed = delta.From != delta.To || delta.SourceChanged || delta.IdentityChanged || len(added) > 0 || len(removed) > 0
	delta.Weakened = decisionStrength(current.Assessment.Decision) < decisionStrength(baseline.Assessment.Decision)
	return delta
}

func decisionStrength(decision models.Decision) int {
	switch decision {
	case models.DecisionBlock:
		return 3
	case models.DecisionRequireApproval:
		return 2
	case models.DecisionAllow:
		return 1
	default:
		return 4
	}
}

func ruleIDs(rules []RuleTrace) []string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID)
	}
	return ids
}

func setDifference(baseline, current []string) (added, removed []string) {
	before := make(map[string]struct{}, len(baseline))
	after := make(map[string]struct{}, len(current))
	for _, value := range baseline {
		before[value] = struct{}{}
	}
	for _, value := range current {
		after[value] = struct{}{}
		if _, exists := before[value]; !exists {
			added = append(added, value)
		}
	}
	for _, value := range baseline {
		if _, exists := after[value]; !exists {
			removed = append(removed, value)
		}
	}
	return added, removed
}

func firstAgent(config policy.Config) string {
	if len(config.Identity.Agents) == 0 {
		return ""
	}
	return config.Identity.Agents[0].ID
}

func sameOrigin(request *http.Request) bool {
	if site := strings.TrimSpace(request.Header.Get("Sec-Fetch-Site")); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || !isLoopbackAuthority(parsed.Host) {
		return false
	}
	expectedScheme := "http"
	if request.TLS != nil {
		expectedScheme = "https"
	}
	return parsed.Scheme == expectedScheme && strings.EqualFold(parsed.Host, request.Host)
}

func isLoopbackAuthority(authority string) bool {
	host := strings.TrimSpace(authority)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func secureHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'none'; frame-ancestors 'none'; img-src 'none'; object-src 'none'; script-src 'self'; style-src 'self'")
	response.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
}

func (handler *Handler) writeError(response http.ResponseWriter, status int, code, message string) {
	value := errorEnvelope{SchemaVersion: SchemaVersion}
	value.Error.Code = code
	value.Error.Message = message
	handler.writeJSON(response, status, value)
}

func (handler *Handler) writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

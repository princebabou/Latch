package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/apiproxy"
	"github.com/princebabou/Latch/internal/approval"
	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/enforcementapi"
	"github.com/princebabou/Latch/internal/mcpadapter"
	"github.com/princebabou/Latch/internal/normalize"
	"github.com/princebabou/Latch/internal/policy"
	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const conformanceAgent = "conformance-agent"

type Report struct {
	SchemaVersion string          `json:"schema_version"`
	SuiteVersion  string          `json:"suite_version"`
	Passed        bool            `json:"passed"`
	Adapters      []AdapterReport `json:"adapters"`
	Total         int             `json:"total"`
	PassedCount   int             `json:"passed_count"`
	FailedCount   int             `json:"failed_count"`
	DurationMS    int64           `json:"duration_ms"`
	Error         string          `json:"error,omitempty"`
}

type AdapterReport struct {
	Name         string        `json:"name"`
	Profile      string        `json:"profile"`
	Passed       bool          `json:"passed"`
	PassedCount  int           `json:"passed_count"`
	FailedCount  int           `json:"failed_count"`
	Requirements []CheckResult `json:"requirements"`
}

type CheckResult struct {
	ID      string `json:"id"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

type observation struct {
	Decision       models.Decision
	DecisionSource string
	Forwarded      bool
	HardDeny       bool
	FailClosed     bool
	TriggeredRules []string
}

type decisionAdapter struct {
	name string
	run  func(context.Context, DecisionCase) (observation, error)
}

// Run executes the embedded suite entirely in-process. Upstream HTTP calls are
// intercepted by a memory transport and no tool or external command executes.
func Run(ctx context.Context) Report {
	started := time.Now()
	manifest, err := LoadManifest()
	if err != nil {
		return Report{SchemaVersion: SchemaVersion, Passed: false, Error: err.Error(), DurationMS: time.Since(started).Milliseconds()}
	}
	report := Report{SchemaVersion: manifest.SchemaVersion, SuiteVersion: manifest.SuiteVersion, Passed: true}
	if err := ctx.Err(); err != nil {
		return Report{
			SchemaVersion: manifest.SchemaVersion, SuiteVersion: manifest.SuiteVersion,
			Passed: false, Total: 1, FailedCount: 1, Error: err.Error(),
			DurationMS: time.Since(started).Milliseconds(),
		}
	}
	adapters := []decisionAdapter{
		{name: "decision-core", run: runDecisionCore},
		{name: "enforcement-api", run: runEnforcementAPI},
		{name: "mcp-stdio", run: func(ctx context.Context, test DecisionCase) (observation, error) { return runMCP(ctx, test, "stdio") }},
		{name: "mcp-streamable-http", run: func(ctx context.Context, test DecisionCase) (observation, error) {
			return runMCP(ctx, test, "streamable-http")
		}},
		{name: "generic-http-api", run: runHTTPProxy},
	}
	for _, adapter := range adapters {
		adapterReport := AdapterReport{Name: adapter.name, Profile: "decision", Passed: true}
		for _, requirement := range manifest.DecisionCases {
			if err := ctx.Err(); err != nil {
				adapterReport.Requirements = append(adapterReport.Requirements, CheckResult{ID: requirement.ID, Message: err.Error()})
				adapterReport.Passed = false
				adapterReport.FailedCount++
				continue
			}
			actual, err := adapter.run(ctx, requirement)
			result := validateDecision(requirement, actual, err)
			adapterReport.Requirements = append(adapterReport.Requirements, result)
			if result.Passed {
				adapterReport.PassedCount++
			} else {
				adapterReport.Passed = false
				adapterReport.FailedCount++
			}
		}
		report.Adapters = append(report.Adapters, adapterReport)
	}

	wireReport := AdapterReport{Name: "enforcement-api-wire", Profile: "wire", Passed: true}
	for _, requirement := range manifest.WireCases {
		status, errorCode, err := runAPIWireCase(ctx, requirement)
		result := CheckResult{ID: requirement.ID, Passed: err == nil && status == requirement.ExpectedStatus && errorCode == requirement.ExpectedError}
		if err != nil {
			result.Message = err.Error()
		} else if !result.Passed {
			result.Message = fmt.Sprintf("got status=%d error=%q; want status=%d error=%q", status, errorCode, requirement.ExpectedStatus, requirement.ExpectedError)
		}
		wireReport.Requirements = append(wireReport.Requirements, result)
		if result.Passed {
			wireReport.PassedCount++
		} else {
			wireReport.Passed = false
			wireReport.FailedCount++
		}
	}
	report.Adapters = append(report.Adapters, wireReport)

	for _, adapter := range report.Adapters {
		report.Total += adapter.PassedCount + adapter.FailedCount
		report.PassedCount += adapter.PassedCount
		report.FailedCount += adapter.FailedCount
		report.Passed = report.Passed && adapter.Passed
	}
	report.DurationMS = time.Since(started).Milliseconds()
	return report
}

func validateDecision(test DecisionCase, actual observation, runErr error) CheckResult {
	result := CheckResult{ID: test.ID}
	if runErr != nil {
		result.Message = runErr.Error()
		return result
	}
	expected := test.Expected
	var differences []string
	if actual.Decision != expected.Decision {
		differences = append(differences, fmt.Sprintf("decision=%s want=%s", actual.Decision, expected.Decision))
	}
	if actual.DecisionSource != expected.DecisionSource {
		differences = append(differences, fmt.Sprintf("source=%s want=%s", actual.DecisionSource, expected.DecisionSource))
	}
	if actual.Forwarded != expected.Forwarded {
		differences = append(differences, fmt.Sprintf("forwarded=%t want=%t", actual.Forwarded, expected.Forwarded))
	}
	if actual.HardDeny != expected.HardDeny {
		differences = append(differences, fmt.Sprintf("hard_deny=%t want=%t", actual.HardDeny, expected.HardDeny))
	}
	if actual.FailClosed != expected.FailClosed {
		differences = append(differences, fmt.Sprintf("fail_closed=%t want=%t", actual.FailClosed, expected.FailClosed))
	}
	for _, rule := range expected.TriggeredRules {
		if !contains(actual.TriggeredRules, rule) {
			differences = append(differences, fmt.Sprintf("missing triggered rule %s", rule))
		}
	}
	result.Passed = len(differences) == 0
	result.Message = strings.Join(differences, "; ")
	return result
}

func runDecisionCore(_ context.Context, test DecisionCase) (observation, error) {
	service, logger, cleanup, err := serviceFor(test)
	if err != nil {
		return observation{}, err
	}
	defer cleanup()
	action, err := normalizedAction(test.Action, nil)
	if err != nil {
		return observation{}, err
	}
	result := service.Decide(action, verifiedIdentity())
	return observeResult(result, logger, result.Assessment.Decision == models.DecisionAllow), nil
}

func runEnforcementAPI(_ context.Context, test DecisionCase) (observation, error) {
	service, logger, cleanup, err := serviceFor(test)
	if err != nil {
		return observation{}, err
	}
	defer cleanup()
	handler, err := enforcementapi.New(enforcementapi.Options{Service: service, AgentID: conformanceAgent})
	if err != nil {
		return observation{}, err
	}
	requestID := "req_" + safeID(test.ID)
	payload, err := json.Marshal(api.DecisionRequest{APIVersion: api.APIVersion, RequestID: requestID, Action: test.Action})
	if err != nil {
		return observation{}, err
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(payload))
	request.Header.Set("Content-Type", api.MediaType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		return observation{}, fmt.Errorf("decision endpoint returned %d: %s", response.Code, response.Body.String())
	}
	var decisionResponse api.DecisionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decisionResponse); err != nil {
		return observation{}, err
	}
	actual := observation{
		Decision: decisionResponse.Decision, DecisionSource: decisionResponse.Policy.DecisionSource,
		Forwarded: decisionResponse.Decision == models.DecisionAllow, HardDeny: decisionResponse.Policy.HardDeny,
		FailClosed: decisionResponse.FailClosed, TriggeredRules: decisionResponse.Policy.TriggeredRules,
	}
	if len(logger.events) == 0 && test.Setup != "audit_unavailable" {
		return observation{}, fmt.Errorf("decision was not audited")
	}
	return actual, nil
}

func runMCP(_ context.Context, test DecisionCase, transport string) (observation, error) {
	service, logger, cleanup, err := serviceFor(test)
	if err != nil {
		return observation{}, err
	}
	defer cleanup()
	inspector, err := mcpadapter.NewInspector(service, transport, io.Discard)
	if err != nil {
		return observation{}, err
	}
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "call_" + safeID(test.ID), "method": "tools/call",
		"params": map[string]any{"name": test.Action.Tool, "arguments": test.Action.Arguments},
	})
	if err != nil {
		return observation{}, err
	}
	outcome, err := inspector.Inspect(mcpadapter.NewSession(conformanceAgent), payload)
	if err != nil {
		return observation{}, err
	}
	if len(logger.events) > 0 {
		assessment := logger.events[len(logger.events)-1].Assessment
		return observationFromAssessment(assessment, outcome.Forward, test.Setup == "audit_unavailable"), nil
	}
	assessment, err := assessmentFromMCPResponse(outcome.Response)
	if err != nil {
		return observation{}, err
	}
	return observationFromAssessment(assessment, outcome.Forward, test.Setup == "audit_unavailable"), nil
}

func runHTTPProxy(_ context.Context, test DecisionCase) (observation, error) {
	service, logger, cleanup, err := serviceFor(test)
	if err != nil {
		return observation{}, err
	}
	defer cleanup()
	forwarded := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		forwarded++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}
	handler, err := apiproxy.New(apiproxy.Options{
		Service: service, AgentID: conformanceAgent,
		UpstreamURL: "https://api.example.test", HTTPClient: client,
	})
	if err != nil {
		return observation{}, err
	}
	method, _ := test.Action.Arguments["method"].(string)
	rawURL, _ := test.Action.Arguments["url"].(string)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return observation{}, err
	}
	var body io.Reader
	if value, ok := test.Action.Arguments["body"]; ok {
		encoded, err := json.Marshal(value)
		if err != nil {
			return observation{}, err
		}
		body = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, "http://latch.local"+parsed.RequestURI(), body)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if len(logger.events) > 0 {
		assessment := logger.events[len(logger.events)-1].Assessment
		return observationFromAssessment(assessment, forwarded == 1, assessment.DecisionSource == "audit_failure"), nil
	}
	if test.Setup == "audit_unavailable" && response.Code == http.StatusServiceUnavailable && forwarded == 0 {
		return observation{Decision: models.DecisionBlock, DecisionSource: "audit_failure", FailClosed: true}, nil
	}
	return observation{}, fmt.Errorf("HTTP adapter produced no audit event; status=%d body=%s", response.Code, response.Body.String())
}

func runAPIWireCase(_ context.Context, test WireCase) (int, string, error) {
	decisionTest := DecisionCase{ID: test.ID, Action: api.Action{Tool: "http.request", Arguments: map[string]any{"method": "GET", "url": "https://api.example.test/status"}}}
	service, _, cleanup, err := serviceFor(decisionTest)
	if err != nil {
		return 0, "", err
	}
	defer cleanup()
	handler, err := enforcementapi.New(enforcementapi.Options{Service: service, AgentID: conformanceAgent, MaxBodyBytes: 1024})
	if err != nil {
		return 0, "", err
	}
	payload := []byte(test.Payload)
	if test.Setup == "replay" {
		payload, err = json.Marshal(api.DecisionRequest{
			APIVersion: api.APIVersion, RequestID: "req_wire_replay",
			Action: api.Action{Tool: "http.request", Arguments: map[string]any{"method": "GET", "url": "https://api.example.test/status"}},
		})
		if err != nil {
			return 0, "", err
		}
		first := apiRequest(handler, payload)
		if first.Code != http.StatusOK {
			return 0, "", fmt.Errorf("initial replay claim returned %d", first.Code)
		}
	}
	if test.Setup == "oversized" {
		payload, err = json.Marshal(api.DecisionRequest{
			APIVersion: api.APIVersion, RequestID: "req_wire_oversized",
			Action: api.Action{Tool: "http.request", Metadata: map[string]any{"padding": strings.Repeat("x", 2048)}},
		})
		if err != nil {
			return 0, "", err
		}
	}
	response := apiRequest(handler, payload)
	var errorResponse api.ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &errorResponse); err != nil {
		return response.Code, "", fmt.Errorf("decode error response: %w", err)
	}
	return response.Code, errorResponse.Error.Code, nil
}

func apiRequest(handler http.Handler, payload []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewReader(payload))
	request.Header.Set("Content-Type", api.MediaType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func serviceFor(test DecisionCase) (*decision.Service, *memoryLogger, func(), error) {
	directory, err := os.MkdirTemp("", "latch-conformance-*")
	if err != nil {
		return nil, nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	config := conformancePolicy(directory)
	logger := &memoryLogger{}
	var auditLogger audit.Logger = logger
	if test.Setup == "audit_unavailable" {
		auditLogger = unavailableLogger{}
	}
	action, err := normalizedAction(test.Action, nil)
	if err != nil {
		cleanup()
		return nil, nil, func() {}, err
	}
	var approvalStore *approval.Store
	if test.Setup == "expired_approval" {
		store, err := approval.NewStore(config)
		if err != nil {
			cleanup()
			return nil, nil, func() {}, err
		}
		base := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		store.Now = func() time.Time { return base }
		if _, err := store.Issue(action, "operator:conformance", time.Minute); err != nil {
			cleanup()
			return nil, nil, func() {}, err
		}
		store.Now = func() time.Time { return base.Add(2 * time.Minute) }
		approvalStore = &store
	}
	service, err := decision.New(config, auditLogger, approvalStore, nil)
	if err != nil {
		cleanup()
		return nil, nil, func() {}, err
	}
	return service, logger, cleanup, nil
}

func conformancePolicy(directory string) policy.Config {
	config := policy.DefaultConfig()
	config.Audit.Path = filepath.Join(directory, "audit.jsonl")
	config.Audit.Terminal = false
	config.Approvals.StorePath = filepath.Join(directory, "approvals.json")
	config.Budgets.StorePath = filepath.Join(directory, "budgets.json")
	config.Identity.RequireVerified = true
	config.Identity.Agents = []policy.AgentIdentity{{ID: conformanceAgent}}
	config.Rules = []policy.Rule{
		{ID: "block-forbidden", Description: "Forbidden endpoints are blocked.", Match: policy.Match{URL: policy.StringList{"https://api.example.test/forbidden/**"}}, Action: models.DecisionBlock},
		{ID: "approve-deploy", Description: "Deployments require approval.", Match: policy.Match{URL: policy.StringList{"https://api.example.test/deploy"}}, Action: models.DecisionRequireApproval},
		{ID: "block-conflict", Priority: 100, Description: "Block wins conflicts.", Match: policy.Match{URL: policy.StringList{"https://api.example.test/conflict/**"}}, Action: models.DecisionBlock},
		{ID: "approve-conflict", Priority: 50, Description: "Conflicting approval.", Match: policy.Match{URL: policy.StringList{"https://api.example.test/conflict/**"}}, Action: models.DecisionRequireApproval},
		{ID: "allow-conflict", Priority: 10, Description: "Conflicting allow.", Match: policy.Match{URL: policy.StringList{"https://api.example.test/conflict/**"}}, Action: models.DecisionAllow},
		{ID: "ordinary-allow-collector", Description: "Ordinary allow cannot bypass hard deny.", Match: policy.Match{URL: policy.StringList{"https://api.example.test/collect"}}, Action: models.DecisionAllow},
	}
	return config
}

func normalizedAction(input api.Action, metadata map[string]any) (models.Action, error) {
	action, err := normalize.Action(normalize.Request{
		AgentID: conformanceAgent, Tool: input.Tool, Arguments: input.Arguments, Metadata: metadata,
	})
	if err != nil {
		return models.Action{}, err
	}
	if strings.TrimSpace(input.Operation) != "" {
		action.Operation = strings.TrimSpace(input.Operation)
	}
	if strings.TrimSpace(input.Resource) != "" {
		action.Resource = strings.TrimSpace(input.Resource)
	}
	return action, nil
}

func verifiedIdentity() models.IdentityContext {
	return models.IdentityContext{ID: conformanceAgent, Verified: true, Source: "conformance"}
}

func observeResult(result decision.Result, logger *memoryLogger, forwarded bool) observation {
	actual := observationFromAssessment(result.Assessment, forwarded, result.OperationalError != nil)
	if len(logger.events) > 0 {
		actual.TriggeredRules = logger.events[len(logger.events)-1].Assessment.TriggeredRules
	}
	return actual
}

func observationFromAssessment(assessment models.Assessment, forwarded, failClosed bool) observation {
	return observation{
		Decision: assessment.Decision, DecisionSource: assessment.DecisionSource,
		Forwarded: forwarded, HardDeny: assessment.HardDeny, FailClosed: failClosed,
		TriggeredRules: append([]string(nil), assessment.TriggeredRules...),
	}
}

func assessmentFromMCPResponse(payload []byte) (models.Assessment, error) {
	var response struct {
		Result struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		return models.Assessment{}, err
	}
	raw := response.Result.Meta["io.latch/security"]
	if len(raw) == 0 {
		return models.Assessment{}, fmt.Errorf("MCP denial omitted Latch security metadata")
	}
	var value struct {
		Decision       models.Decision `json:"decision"`
		DecisionSource string          `json:"decision_source"`
		HardDeny       bool            `json:"hard_deny"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return models.Assessment{}, err
	}
	return models.Assessment{Decision: value.Decision, DecisionSource: value.DecisionSource, HardDeny: value.HardDeny}, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func safeID(value string) string {
	value = strings.NewReplacer(".", "_", "-", "_").Replace(value)
	if len(value) > 96 {
		value = value[:96]
	}
	return value
}

type memoryLogger struct{ events []models.AuditEvent }

func (logger *memoryLogger) Write(event models.AuditEvent) error {
	logger.events = append(logger.events, event)
	return nil
}

type unavailableLogger struct{}

func (unavailableLogger) Write(models.AuditEvent) error {
	return errors.New("conformance audit unavailable")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func SortedAdapterNames(report Report) []string {
	names := make([]string, 0, len(report.Adapters))
	for _, adapter := range report.Adapters {
		names = append(names, adapter.Name)
	}
	sort.Strings(names)
	return names
}

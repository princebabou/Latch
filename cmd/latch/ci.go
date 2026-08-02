package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/cireport"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/normalize"
	"github.com/princebabou/Latch/internal/strictjson"
	v1 "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const maxCIArgumentsJSON = 256 << 10

func ciGate(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	providerName := fs.String("provider", "auto", "CI provider: auto, generic, or github")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted CI agent identity")
	tool := fs.String("tool", "", "tool name")
	operation := fs.String("action", "", "normalized operation override")
	resource := fs.String("resource", "", "resource override")
	argumentsJSON := fs.String("arguments-json", "", "strict JSON object of action arguments")
	argumentsJSONEnv := fs.String("arguments-json-env", "", "environment variable containing the strict JSON arguments object")
	jsonOutput := fs.Bool("json", false, "emit the stable v1 decision response")
	var rawArgs stringSlice
	fs.Var(&rawArgs, "arg", "argument in key=value form; repeatable")
	if err := fs.Parse(args); err != nil {
		return 64
	}

	environment := ciEnvironment()
	provider, err := cireport.ResolveProvider(*providerName, environment)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	if strings.TrimSpace(*agent) == "" {
		fmt.Fprintln(errOut, "--agent is required")
		return 64
	}
	if strings.TrimSpace(*tool) == "" {
		fmt.Fprintln(errOut, "--tool is required")
		return 64
	}

	requestID, err := v1.NewRequestID()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	argumentsPayload, err := ciArgumentsPayload(*argumentsJSON, *argumentsJSONEnv)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	arguments, err := parseCIArguments(argumentsPayload, rawArgs)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	action, err := normalize.Action(normalize.Request{
		AgentID:   strings.TrimSpace(*agent),
		Tool:      strings.TrimSpace(*tool),
		Arguments: arguments,
		Metadata:  ciMetadata(provider),
	})
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	if strings.TrimSpace(*operation) != "" {
		action.Operation = strings.TrimSpace(*operation)
	}
	if strings.TrimSpace(*resource) != "" {
		action.Resource = strings.TrimSpace(*resource)
	}
	identity := models.IdentityContext{ID: action.AgentID, Verified: true, Source: "ci_adapter"}

	config, err := loadConfig(*configPath)
	if err != nil {
		return reportCIFailure(provider, environment, requestID, action, *jsonOutput, out, errOut, err)
	}
	service, err := decision.New(config, nil, nil, nil)
	if err != nil {
		return reportCIFailure(provider, environment, requestID, action, *jsonOutput, out, errOut, err)
	}
	result := service.Decide(action, identity)
	failClosed := result.OperationalError != nil
	report := cireport.Result{
		RequestID: requestID, Action: result.Action,
		Assessment: result.Assessment, FailClosed: failClosed,
	}
	if provider == cireport.ProviderGitHub {
		if err := cireport.WriteGitHub(out, environment, report); err != nil {
			fmt.Fprintf(errOut, "report CI decision: %v\n", err)
			return 1
		}
	}
	printCIResult(out, report, *jsonOutput)
	if config.Audit.Terminal {
		fmt.Fprintln(errOut, audit.Terminal(result.Event))
	}
	if result.OperationalError != nil {
		fmt.Fprintln(errOut, decision.Diagnostic(result))
		return 1
	}
	if result.Assessment.Decision == models.DecisionAllow {
		return 0
	}
	return 3
}

func ciArgumentsPayload(direct, environmentName string) (string, error) {
	direct = strings.TrimSpace(direct)
	environmentName = strings.TrimSpace(environmentName)
	if direct != "" && environmentName != "" {
		return "", fmt.Errorf("--arguments-json and --arguments-json-env are mutually exclusive")
	}
	if environmentName == "" {
		if direct == "" {
			return "{}", nil
		}
		return direct, nil
	}
	if !validEnvironmentName(environmentName) {
		return "", fmt.Errorf("--arguments-json-env must name a portable environment variable")
	}
	payload, present := os.LookupEnv(environmentName)
	if !present {
		return "", fmt.Errorf("environment variable %s is not set", environmentName)
	}
	return payload, nil
}

func parseCIArguments(payload string, rawArgs []string) (map[string]any, error) {
	if len(payload) > maxCIArgumentsJSON {
		return nil, fmt.Errorf("--arguments-json cannot exceed %d bytes", maxCIArgumentsJSON)
	}
	arguments := map[string]any{}
	if err := strictjson.Decode([]byte(payload), &arguments); err != nil {
		return nil, fmt.Errorf("invalid --arguments-json: %w", err)
	}
	additional, err := parseArguments(rawArgs)
	if err != nil {
		return nil, err
	}
	for key, value := range additional {
		if _, duplicate := arguments[key]; duplicate {
			return nil, fmt.Errorf("argument %q is defined by both --arguments-json and --arg", key)
		}
		arguments[key] = value
	}
	return arguments, nil
}

func reportCIFailure(provider cireport.Provider, environment cireport.Environment, requestID string, action models.Action, jsonOutput bool, out, errOut io.Writer, cause error) int {
	assessment := models.Assessment{
		Decision: models.DecisionBlock, DecisionSource: "ci_adapter_failure",
		RiskLevel: "UNKNOWN", Reasons: []string{"Latch could not complete enforcement safely"},
	}
	report := cireport.Result{RequestID: requestID, Action: action, Assessment: assessment, FailClosed: true}
	if provider == cireport.ProviderGitHub {
		if err := cireport.WriteGitHub(out, environment, report); err != nil {
			fmt.Fprintf(errOut, "report CI failure: %v\n", err)
		}
	}
	printCIResult(out, report, jsonOutput)
	fmt.Fprintf(errOut, "Latch CI fail-closed: %v\n", cause)
	return 1
}

func printCIResult(out io.Writer, result cireport.Result, jsonOutput bool) {
	if jsonOutput {
		response := v1.Response(result.RequestID, result.Assessment, result.FailClosed)
		_ = json.NewEncoder(out).Encode(response)
		return
	}
	printAssessment(out, result.Action, result.Assessment, true)
}

func ciEnvironment() cireport.Environment {
	return cireport.Environment{
		GitHubActions: os.Getenv("GITHUB_ACTIONS"),
		OutputPath:    os.Getenv("GITHUB_OUTPUT"),
		SummaryPath:   os.Getenv("GITHUB_STEP_SUMMARY"),
	}
}

func ciMetadata(provider cireport.Provider) map[string]any {
	metadata := map[string]any{"ci_provider": string(provider)}
	if provider != cireport.ProviderGitHub {
		return metadata
	}
	for key, environmentKey := range map[string]string{
		"ci_repository":  "GITHUB_REPOSITORY",
		"ci_workflow":    "GITHUB_WORKFLOW",
		"ci_job":         "GITHUB_JOB",
		"ci_ref":         "GITHUB_REF",
		"ci_sha":         "GITHUB_SHA",
		"ci_event":       "GITHUB_EVENT_NAME",
		"ci_run_id":      "GITHUB_RUN_ID",
		"ci_run_attempt": "GITHUB_RUN_ATTEMPT",
	} {
		if value := strings.TrimSpace(os.Getenv(environmentKey)); value != "" {
			metadata[key] = value
		}
	}
	return metadata
}

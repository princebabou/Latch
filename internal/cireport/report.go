// Package cireport renders Latch decisions for continuous-integration systems.
package cireport

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/princebabou/Latch/pkg/models"
)

// Provider identifies the CI reporting protocol to use.
type Provider string

const (
	ProviderAuto    Provider = "auto"
	ProviderGeneric Provider = "generic"
	ProviderGitHub  Provider = "github"
)

// Environment contains the runner-owned files used by GitHub Actions.
type Environment struct {
	GitHubActions string
	OutputPath    string
	SummaryPath   string
}

// Result is the provider-neutral decision report.
type Result struct {
	RequestID  string
	Action     models.Action
	Assessment models.Assessment
	FailClosed bool
}

// ResolveProvider validates a provider name and performs conservative
// auto-detection. Generic mode never writes runner environment files.
func ResolveProvider(value string, environment Environment) (Provider, error) {
	provider := Provider(strings.ToLower(strings.TrimSpace(value)))
	if provider == "" {
		provider = ProviderAuto
	}
	switch provider {
	case ProviderAuto:
		if strings.EqualFold(strings.TrimSpace(environment.GitHubActions), "true") {
			return ProviderGitHub, nil
		}
		return ProviderGeneric, nil
	case ProviderGeneric, ProviderGitHub:
		return provider, nil
	default:
		return "", fmt.Errorf("unsupported CI provider %q; expected auto, generic, or github", value)
	}
}

// WriteGitHub emits a safely escaped annotation, action outputs, and job
// summary. Any missing or unwritable runner file is an error so the gate fails
// closed instead of silently losing its contract with later workflow steps.
func WriteGitHub(log io.Writer, environment Environment, result Result) error {
	if strings.TrimSpace(environment.OutputPath) == "" {
		return fmt.Errorf("GITHUB_OUTPUT is unavailable")
	}
	if strings.TrimSpace(environment.SummaryPath) == "" {
		return fmt.Errorf("GITHUB_STEP_SUMMARY is unavailable")
	}

	annotation, message := annotationFor(result)
	fmt.Fprintf(log, "::%s title=Latch policy gate::%s\n", annotation, escapeWorkflowData(message))

	outputs, err := githubOutputs(result)
	if err != nil {
		return err
	}
	if err := appendFile(environment.SummaryPath, []byte(githubSummary(result))); err != nil {
		return fmt.Errorf("write GitHub job summary: %w", err)
	}
	// Outputs are written last. A later workflow step can only observe an
	// ALLOW after every required reporting channel has succeeded.
	if err := appendFile(environment.OutputPath, outputs); err != nil {
		return fmt.Errorf("write GitHub action outputs: %w", err)
	}
	return nil
}

func annotationFor(result Result) (string, string) {
	decision := result.Assessment.Decision
	message := fmt.Sprintf("%s for %s (risk %s %d/100; source %s)",
		decision,
		singleLine(result.Action.Tool),
		singleLine(result.Assessment.RiskLevel),
		result.Assessment.RiskScore,
		singleLine(result.Assessment.DecisionSource),
	)
	if result.FailClosed {
		return "error", "BLOCK: Latch could not complete enforcement safely; the action is fail-closed"
	}
	switch decision {
	case models.DecisionAllow:
		return "notice", message
	case models.DecisionRequireApproval:
		return "warning", message
	default:
		return "error", message
	}
}

func githubOutputs(result Result) ([]byte, error) {
	triggeredRuleValues := result.Assessment.TriggeredRules
	if triggeredRuleValues == nil {
		triggeredRuleValues = []string{}
	}
	reasonValues := result.Assessment.Reasons
	if reasonValues == nil {
		reasonValues = []string{}
	}
	triggeredRules, err := json.Marshal(triggeredRuleValues)
	if err != nil {
		return nil, fmt.Errorf("encode triggered rules: %w", err)
	}
	reasons, err := json.Marshal(reasonValues)
	if err != nil {
		return nil, fmt.Errorf("encode decision reasons: %w", err)
	}
	values := [][2]string{
		{"request_id", result.RequestID},
		{"decision", string(result.Assessment.Decision)},
		{"allowed", strconv.FormatBool(result.Assessment.Decision == models.DecisionAllow && !result.FailClosed)},
		{"approval_required", strconv.FormatBool(result.Assessment.Decision == models.DecisionRequireApproval)},
		{"fail_closed", strconv.FormatBool(result.FailClosed)},
		{"risk_score", strconv.Itoa(result.Assessment.RiskScore)},
		{"risk_level", result.Assessment.RiskLevel},
		{"decision_source", result.Assessment.DecisionSource},
		{"hard_deny", strconv.FormatBool(result.Assessment.HardDeny)},
		{"triggered_rules", string(triggeredRules)},
		{"reasons", string(reasons)},
	}
	var output strings.Builder
	for _, item := range values {
		value := item[1]
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("output %q contains an unsafe line break", item[0])
		}
		fmt.Fprintf(&output, "%s=%s\n", item[0], value)
	}
	return []byte(output.String()), nil
}

func githubSummary(result Result) string {
	assessment := result.Assessment
	status := string(assessment.Decision)
	if result.FailClosed {
		status = "BLOCK (fail-closed)"
	}
	var summary strings.Builder
	fmt.Fprintln(&summary, "## Latch policy gate")
	fmt.Fprintln(&summary)
	fmt.Fprintf(&summary, "| Result | Value |\n| --- | --- |\n")
	fmt.Fprintf(&summary, "| Decision | **%s** |\n", markdownText(status))
	fmt.Fprintf(&summary, "| Tool | %s |\n", markdownText(result.Action.Tool))
	fmt.Fprintf(&summary, "| Operation | %s |\n", markdownText(displayValue(result.Action.Operation)))
	fmt.Fprintf(&summary, "| Resource | %s |\n", markdownText(displayValue(result.Action.Resource)))
	fmt.Fprintf(&summary, "| Risk | %s (%d/100) |\n", markdownText(assessment.RiskLevel), assessment.RiskScore)
	fmt.Fprintf(&summary, "| Source | %s |\n", markdownText(assessment.DecisionSource))
	fmt.Fprintf(&summary, "| Request ID | %s |\n", markdownText(result.RequestID))
	if len(assessment.TriggeredRules) > 0 {
		fmt.Fprintln(&summary, "\n### Triggered rules")
		for _, rule := range assessment.TriggeredRules {
			fmt.Fprintf(&summary, "\n- %s", markdownText(rule))
		}
		fmt.Fprintln(&summary)
	}
	if len(assessment.Reasons) > 0 {
		fmt.Fprintln(&summary, "\n### Reasons")
		for _, reason := range assessment.Reasons {
			fmt.Fprintf(&summary, "\n- %s", markdownText(reason))
		}
		fmt.Fprintln(&summary)
	}
	return summary.String()
}

func appendFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func escapeWorkflowData(value string) string {
	replacer := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return replacer.Replace(value)
}

func displayValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func singleLine(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	return strings.TrimSpace(value)
}

func markdownText(value string) string {
	value = singleLine(value)
	replacer := strings.NewReplacer(
		"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_",
		"{", "\\{", "}", "\\}", "[", "\\[", "]", "\\]",
		"(", "\\(", ")", "\\)", "<", "&lt;", ">", "&gt;",
		"#", "\\#", "+", "\\+", "-", "\\-", "!", "\\!", "|", "\\|",
	)
	return replacer.Replace(value)
}

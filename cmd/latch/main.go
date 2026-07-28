// Latch is a security firewall for AI agent actions.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/latch-security/latch/internal/approval"
	"github.com/latch-security/latch/internal/audit"
	"github.com/latch-security/latch/internal/enforce"
	"github.com/latch-security/latch/internal/normalize"
	"github.com/latch-security/latch/internal/policy"
	"github.com/latch-security/latch/pkg/models"
)

const defaultConfigPath = "configs/latch.example.yaml"

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 || isHelp(args[0]) {
		usage(out)
		return 0
	}
	switch args[0] {
	case "check":
		return check(args[1:], in, out, errOut)
	case "run":
		return runFile(args[1:], out, errOut)
	case "policies":
		return policies(args[1:], out, errOut)
	case "logs":
		return logs(args[1:], out, errOut)
	case "version", "--version", "-v":
		fmt.Fprintln(out, "latch dev")
		return 0
	default:
		fmt.Fprintf(errOut, "Unknown command %q.\n\n", args[0])
		usage(errOut)
		return 64
	}
}

func usage(out io.Writer) {
	fmt.Fprint(out, `Latch — a security firewall for AI agent actions

Usage:
  latch check --tool <name> [--arg key=value] [options]
  latch run --input <actions.jsonl> [--config policy.yaml]
  latch policies list|validate [--config policy.yaml]
  latch logs [--config policy.yaml] [--tail 20]

Examples:
  latch check --tool filesystem.read --arg path=./README.md
  latch check --tool filesystem.read --arg path=~/.ssh/id_rsa
  latch check --tool shell.exec --arg "command=npm test" --interactive
  latch run --input examples/actions.jsonl

The standalone CLI evaluates requests and never executes them.
`)
}

type stringSlice []string

func (s *stringSlice) String() string         { return strings.Join(*s, ",") }
func (s *stringSlice) Set(value string) error { *s = append(*s, value); return nil }

func check(args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigPath, "YAML policy file")
	tool := fs.String("tool", "", "tool name")
	agent := fs.String("agent", "cli", "agent identity")
	operation := fs.String("action", "", "normalized operation override")
	resource := fs.String("resource", "", "resource override")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	interactive := fs.Bool("interactive", false, "prompt if approval is required")
	var rawArgs stringSlice
	fs.Var(&rawArgs, "arg", "argument in key=value form; repeatable")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if strings.TrimSpace(*tool) == "" {
		fmt.Fprintln(errOut, "--tool is required")
		return 64
	}
	arguments, err := parseArguments(rawArgs)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	action, err := normalize.Action(normalize.Request{AgentID: *agent, Tool: *tool, Arguments: arguments})
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	if *operation != "" {
		action.Operation = *operation
	}
	if *resource != "" {
		action.Resource = *resource
	}
	return evaluateOne(*configPath, action, *interactive, in, out, errOut, *jsonOutput)
}

func runFile(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigPath, "YAML policy file")
	inputFile := fs.String("input", "", "JSON Lines input file")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if *inputFile == "" {
		fmt.Fprintln(errOut, "--input is required")
		return 64
	}
	file, err := os.Open(*inputFile)
	if err != nil {
		fmt.Fprintf(errOut, "open input: %v\n", err)
		return 1
	}
	defer file.Close()
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	code := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for line := 1; scanner.Scan(); line++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var input struct {
			AgentID   string         `json:"agent_id"`
			Tool      string         `json:"tool"`
			Arguments map[string]any `json:"arguments"`
			Metadata  map[string]any `json:"metadata"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &input); err != nil {
			fmt.Fprintf(errOut, "%s:%d: invalid JSON: %v\n", *inputFile, line, err)
			code = 1
			continue
		}
		action, err := normalize.Action(normalize.Request{AgentID: input.AgentID, Tool: input.Tool, Arguments: input.Arguments, Metadata: input.Metadata})
		if err != nil {
			fmt.Fprintf(errOut, "%s:%d: %v\n", *inputFile, line, err)
			code = 1
			continue
		}
		assessment, err := evaluate(config, action)
		if err != nil {
			fmt.Fprintln(errOut, err)
			code = 1
			continue
		}
		printAssessment(out, action, assessment, false)
		if assessment.Decision != models.DecisionAllow && code == 0 {
			code = 3
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(errOut, "read input: %v\n", err)
		return 1
	}
	return code
}

func policies(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "Usage: latch policies list|validate [--config policy.yaml]")
		return 64
	}
	fs := flag.NewFlagSet("policies "+args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigPath, "YAML policy file")
	if err := fs.Parse(args[1:]); err != nil {
		return 64
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	switch args[0] {
	case "validate":
		fmt.Fprintf(out, "Policy valid: %s (%d rules)\n", *configPath, len(config.Rules))
		return 0
	case "list":
		for _, rule := range config.Rules {
			description := rule.Description
			if description == "" {
				description = "(no description)"
			}
			fmt.Fprintf(out, "%s\t%s\t%s\n", rule.ID, rule.Action, description)
		}
		return 0
	default:
		fmt.Fprintf(errOut, "Unknown policies command %q\n", args[0])
		return 64
	}
}

func logs(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigPath, "YAML policy file")
	tail := fs.Int("tail", 20, "number of recent events")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	data, err := os.ReadFile(config.Audit.Path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(out, "No audit events recorded.")
		return 0
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		fmt.Fprintln(out, "No audit events recorded.")
		return 0
	}
	start := len(lines) - *tail
	if start < 0 {
		start = 0
	}
	for _, line := range lines[start:] {
		fmt.Fprintln(out, line)
	}
	return 0
}

func evaluateOne(configPath string, action models.Action, interactive bool, in io.Reader, out, errOut io.Writer, jsonOutput bool) int {
	config, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	assessment, approvalStatus, err := evaluateWithApproval(config, action, interactive, in, out)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	event := audit.NewEvent(action, assessment, approvalStatus)
	if err := (audit.JSONLLogger{Path: config.Audit.Path}).Write(event); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if jsonOutput {
		_ = json.NewEncoder(out).Encode(struct {
			Action     models.Action     `json:"action"`
			Assessment models.Assessment `json:"assessment"`
		}{audit.RedactAction(action), assessment})
	} else {
		printAssessment(out, action, assessment, true)
	}
	if config.Audit.Terminal {
		fmt.Fprintln(errOut, audit.Terminal(event))
	}
	if assessment.Decision == models.DecisionAllow {
		return 0
	}
	return 3
}

func evaluate(config policy.Config, action models.Action) (models.Assessment, error) {
	assessment := enforce.Evaluate(config, action)
	event := audit.NewEvent(action, assessment, "")
	if err := (audit.JSONLLogger{Path: config.Audit.Path}).Write(event); err != nil {
		return models.Assessment{}, err
	}
	return assessment, nil
}

func evaluateWithApproval(config policy.Config, action models.Action, interactive bool, in io.Reader, out io.Writer) (models.Assessment, string, error) {
	assessment := enforce.Evaluate(config, action)
	if assessment.Decision != models.DecisionRequireApproval {
		return assessment, "", nil
	}
	store := approval.Store{Path: filepath.Join(filepath.Dir(config.Audit.Path), "approvals.json")}
	allowed, err := store.IsAllowed(action)
	if err != nil {
		return assessment, "", fmt.Errorf("read local approvals: %w", err)
	}
	if allowed {
		assessment.Decision = models.DecisionAllow
		assessment.Reasons = append(assessment.Reasons, "Previously approved exact action")
		return assessment, "previously_allowed", nil
	}
	if !interactive {
		return assessment, "pending", nil
	}
	choice, err := approval.Prompt(in, out, action, assessment)
	if err != nil {
		return assessment, "", err
	}
	switch choice {
	case approval.AllowOnce:
		assessment.Decision = models.DecisionAllow
		assessment.Reasons = append(assessment.Reasons, "Allowed once by operator")
	case approval.AlwaysAllow:
		if err := store.Allow(action); err != nil {
			return assessment, "", fmt.Errorf("save local approval: %w", err)
		}
		assessment.Decision = models.DecisionAllow
		assessment.Reasons = append(assessment.Reasons, "Allowed by operator for this exact action")
	case approval.Deny:
		assessment.Decision = models.DecisionBlock
		assessment.Reasons = append(assessment.Reasons, "Denied by operator")
	}
	return assessment, string(choice), nil
}

func loadConfig(path string) (policy.Config, error) {
	if path == "" {
		return policy.DefaultConfig(), nil
	}
	config, err := policy.Load(path)
	if err != nil {
		return policy.Config{}, fmt.Errorf("load policy: %w", err)
	}
	return config, nil
}

func parseArguments(raw []string) (map[string]any, error) {
	arguments := map[string]any{}
	for _, pair := range raw {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("invalid --arg %q; expected key=value", pair)
		}
		arguments[key] = parseValue(value)
	}
	return arguments, nil
}

func parseValue(raw string) any {
	if raw == "true" || raw == "false" {
		value, _ := strconv.ParseBool(raw)
		return value
	}
	if number, err := strconv.Atoi(raw); err == nil {
		return number
	}
	if (strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[")) && json.Valid([]byte(raw)) {
		var value any
		_ = json.Unmarshal([]byte(raw), &value)
		return value
	}
	return raw
}

func printAssessment(out io.Writer, action models.Action, assessment models.Assessment, detailed bool) {
	fmt.Fprintln(out, "LATCH")
	fmt.Fprintf(out, "\nDecision: %s\nRisk: %s (%d/100)\n", assessment.Decision, assessment.RiskLevel, assessment.RiskScore)
	if detailed && action.Resource != "" {
		fmt.Fprintf(out, "Tool: %s\nResource: %s\n", action.Tool, action.Resource)
	}
	if len(assessment.TriggeredRules) > 0 {
		fmt.Fprintln(out, "\nTriggered:")
		for _, rule := range assessment.TriggeredRules {
			fmt.Fprintf(out, "- %s\n", rule)
		}
	}
	if len(assessment.Reasons) > 0 {
		fmt.Fprintln(out, "\nReason:")
		for _, reason := range assessment.Reasons {
			fmt.Fprintf(out, "- %s\n", reason)
		}
	}
	if len(assessment.Signals) > 0 {
		fmt.Fprintln(out, "\nSignals:")
		for _, signal := range assessment.Signals {
			fmt.Fprintf(out, "- +%d %s\n", signal.Score, signal.Description)
		}
	}
	fmt.Fprintln(out)
}

func isHelp(value string) bool { return value == "help" || value == "--help" || value == "-h" }

// Latch is a security firewall for AI agent actions.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/approval"
	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/budget"
	"github.com/princebabou/Latch/internal/enforce"
	"github.com/princebabou/Latch/internal/mcpstdio"
	"github.com/princebabou/Latch/internal/normalize"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

const defaultConfigPath = "latch.yaml"

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
	case "proxy":
		return proxy(args[1:], in, out, errOut)
	case "serve":
		return serve(args[1:], out, errOut)
	case "policies":
		return policies(args[1:], out, errOut)
	case "identities":
		return identities(args[1:], out, errOut)
	case "budgets":
		return budgets(args[1:], out, errOut)
	case "init":
		return initConfig(args[1:], out, errOut)
	case "doctor":
		return doctor(args[1:], out, errOut)
	case "integrations":
		return integrations(args[1:], out, errOut)
	case "approvals":
		return approvals(args[1:], out, errOut)
	case "logs":
		return logs(args[1:], out, errOut)
	case "version", "--version", "-v":
		return versionCommand(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "Unknown command %q.\n\n", args[0])
		usage(errOut)
		return 64
	}
}

func usage(out io.Writer) {
	fmt.Fprint(out, `Latch - a security firewall for AI agent actions

Usage:
  latch init [--profile balanced|strict|developer] [--output latch.yaml]
  latch doctor [--config policy.yaml] [--agent <trusted-id>] [-- server [args...]]
  latch integrations mcp --client <claude|cursor|vscode|generic> [options] -- server [args...]
  latch check --tool <name> [--arg key=value] [options]
  latch proxy [options] -- <mcp-server-command> [args...]
  latch serve [--listen 127.0.0.1:7070] [--agent <trusted-id>] [options]
  latch run --input <actions.jsonl> [--config policy.yaml] [--agent <trusted-id>]
  latch policies list|validate [--config policy.yaml]
  latch identities list [--config policy.yaml] [--json]
  latch budgets status --agent <trusted-id> [--config policy.yaml] [--json]
  latch approvals list|revoke|prune [options]
  latch logs [--config policy.yaml] [--tail 20]
  latch version [--json]

Examples:
  latch init --profile balanced --agent desktop-agent
  latch doctor --agent desktop-agent -- my-mcp-server
  latch integrations mcp --client vscode --name protected --agent desktop-agent -- my-mcp-server
  latch check --tool filesystem.read --arg path=./README.md
  latch check --tool filesystem.read --arg path=~/.ssh/id_rsa
  latch check --tool shell.exec --arg "command=npm test" --interactive
  latch proxy --agent claude-desktop -- ./my-mcp-server
  latch run --input examples/actions.jsonl

The check and run commands only evaluate requests. The proxy command launches
the named MCP server and forwards only tool calls that Latch allows.
`)
}

type stringSlice []string

func (s *stringSlice) String() string         { return strings.Join(*s, ",") }
func (s *stringSlice) Set(value string) error { *s = append(*s, value); return nil }

func check(args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	tool := fs.String("tool", "", "tool name")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", "cli"), "agent identity")
	operation := fs.String("action", "", "normalized operation override")
	resource := fs.String("resource", "", "resource override")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	interactive := fs.Bool("interactive", false, "prompt if approval is required")
	approver := fs.String("approver", defaultApprover(), "operator identity recorded with an approval")
	approvalTTL := fs.Duration("approval-ttl", 0, "duration for a time-bound approval; defaults to policy")
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
	identity := models.IdentityContext{ID: *agent, Verified: true, Source: "cli_argument"}
	return evaluateOne(*configPath, action, identity, *interactive, in, out, errOut, *jsonOutput, grantOptions{Approver: *approver, TTL: *approvalTTL})
}

func proxy(args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted agent identity override")
	directory := fs.String("cwd", "", "working directory for the MCP server")
	maxMessageBytes := fs.Int("max-message-bytes", 4<<20, "maximum MCP JSON-RPC message size")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	command := fs.Args()
	if len(command) == 0 {
		fmt.Fprintln(errOut, "an MCP server command is required after --")
		return 64
	}
	if *maxMessageBytes < 1024 {
		fmt.Fprintln(errOut, "--max-message-bytes must be at least 1024")
		return 64
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	fmt.Fprintf(errOut, "Latch MCP proxy: enforcing %d rules for %s\n", len(config.Rules), command[0])
	err = mcpstdio.Run(ctx, mcpstdio.Options{
		Policy:          config,
		AgentID:         *agent,
		Command:         command[0],
		Arguments:       command[1:],
		Directory:       *directory,
		MaxMessageBytes: *maxMessageBytes,
		Input:           in,
		Output:          out,
		ErrorOutput:     errOut,
	})
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	fmt.Fprintf(errOut, "Latch MCP proxy stopped: %v\n", err)
	return 1
}

func runFile(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	inputFile := fs.String("input", "", "JSON Lines input file")
	trustedAgent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted identity bound to every input action")
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
		identity := models.IdentityContext{ID: action.AgentID, Verified: false, Source: "batch_input"}
		if strings.TrimSpace(*trustedAgent) != "" {
			action.AgentID = strings.TrimSpace(*trustedAgent)
			identity = models.IdentityContext{ID: action.AgentID, Verified: true, Source: "cli_argument"}
		}
		assessment, err := evaluate(config, action, identity)
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

func identities(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "Usage: latch identities list [--config policy.yaml] [--json]")
		return 64
	}
	command := args[0]
	fs := flag.NewFlagSet("identities "+command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 64
	}
	if command != "list" {
		fmt.Fprintf(errOut, "Unknown identities command %q\n", command)
		return 64
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if *jsonOutput {
		_ = json.NewEncoder(out).Encode(config.Identity)
		return 0
	}
	fmt.Fprintf(out, "Require verified: %t\nCapability enforcement: %t\n", config.Identity.RequireVerified, config.Identity.EnforceCapabilities)
	if len(config.Identity.Agents) == 0 {
		fmt.Fprintln(out, "No agent identities registered.")
		return 0
	}
	fmt.Fprintln(out, "\nID\tALIASES\tCAPABILITIES")
	for _, agent := range config.Identity.Agents {
		aliases := strings.Join(agent.Aliases, ",")
		if aliases == "" {
			aliases = "-"
		}
		capabilityIDs := make([]string, 0, len(agent.Capabilities))
		for _, capability := range agent.Capabilities {
			capabilityIDs = append(capabilityIDs, capability.ID)
		}
		capabilities := strings.Join(capabilityIDs, ",")
		if capabilities == "" {
			capabilities = "-"
		}
		fmt.Fprintf(out, "%s\t%s\t%s\n", agent.ID, aliases, capabilities)
	}
	return 0
}

func budgets(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "Usage: latch budgets status --agent <trusted-id> [--config policy.yaml] [--json]")
		return 64
	}
	command := args[0]
	fs := flag.NewFlagSet("budgets "+command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted agent identity")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 64
	}
	if command != "status" {
		fmt.Fprintf(errOut, "Unknown budgets command %q\n", command)
		return 64
	}
	if strings.TrimSpace(*agent) == "" {
		fmt.Fprintln(errOut, "--agent is required")
		return 64
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	agentID := strings.TrimSpace(*agent)
	if canonical, known := policy.CanonicalAgentID(config, agentID); known {
		agentID = canonical
	}
	store, err := budget.NewStore(config)
	if err != nil {
		fmt.Fprintf(errOut, "configure action budgets: %v\n", err)
		return 1
	}
	statuses, err := store.Status(agentID)
	if err != nil {
		fmt.Fprintf(errOut, "read action budgets: %v\n", err)
		return 1
	}
	if *jsonOutput {
		_ = json.NewEncoder(out).Encode(struct {
			AgentID string                `json:"agent_id"`
			Budgets []models.BudgetStatus `json:"budgets"`
		}{AgentID: agentID, Budgets: statuses})
		return 0
	}
	fmt.Fprintf(out, "Agent: %s\n", agentID)
	if len(statuses) == 0 {
		fmt.Fprintln(out, "No action budgets configured.")
		return 0
	}
	fmt.Fprintln(out, "\nBUDGET\tUSED\tLIMIT\tWINDOW\tREMAINING\tRETRY AFTER")
	for _, status := range statuses {
		retryAfter := status.RetryAfter
		if retryAfter == "" {
			retryAfter = "-"
		}
		fmt.Fprintf(out, "%s\t%d\t%d\t%s\t%d\t%s\n",
			status.RuleID, status.Used, status.Limit, status.Window, status.Remaining, retryAfter)
	}
	return 0
}

func policies(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "Usage: latch policies list|validate [--config policy.yaml]")
		return 64
	}
	fs := flag.NewFlagSet("policies "+args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
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

func approvals(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "Usage: latch approvals list|revoke|prune [options]")
		return 64
	}
	command := args[0]
	fs := flag.NewFlagSet("approvals "+command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	id := fs.String("id", "", "approval grant id")
	actor := fs.String("approver", defaultApprover(), "operator identity")
	reason := fs.String("reason", "", "revocation reason")
	if err := fs.Parse(args[1:]); err != nil {
		return 64
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	store, err := approval.NewStore(config)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	switch command {
	case "list":
		grants, err := store.List()
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		if *jsonOutput {
			_ = json.NewEncoder(out).Encode(grants)
			return 0
		}
		if len(grants) == 0 {
			fmt.Fprintln(out, "No approval grants recorded.")
			return 0
		}
		fmt.Fprintln(out, "ID\tSTATUS\tAGENT\tTOOL\tEXPIRES\tAPPROVER\tRESOURCE")
		for _, grant := range grants {
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", grant.ID, grant.Status, grant.AgentID, grant.Tool, formatGrantTime(grant.ExpiresAt), grant.Approver, grant.Resource)
		}
		return 0
	case "revoke":
		if strings.TrimSpace(*id) == "" || strings.TrimSpace(*reason) == "" {
			fmt.Fprintln(errOut, "--id and --reason are required")
			return 64
		}
		grant, err := store.Revoke(*id, *actor, *reason)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		fmt.Fprintf(out, "Revoked approval %s for %s by %s.\n", grant.ID, grant.Tool, grant.RevokedBy)
		return 0
	case "prune":
		removed, err := store.Prune()
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		fmt.Fprintf(out, "Removed %d inactive approval grant(s).\n", removed)
		return 0
	default:
		fmt.Fprintf(errOut, "Unknown approvals command %q\n", command)
		return 64
	}
}

func logs(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
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

type grantOptions struct {
	Approver string
	TTL      time.Duration
}

func evaluateOne(configPath string, action models.Action, identity models.IdentityContext, interactive bool, in io.Reader, out, errOut io.Writer, jsonOutput bool, grantOptions grantOptions) int {
	config, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	action, identity = enforce.CanonicalizeIdentity(config, action, identity)
	assessment, approvalStatus, err := evaluateWithApproval(config, action, identity, interactive, in, out, grantOptions)
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

func evaluate(config policy.Config, action models.Action, identity models.IdentityContext) (models.Assessment, error) {
	action, identity = enforce.CanonicalizeIdentity(config, action, identity)
	assessment := enforce.EvaluateWithIdentity(config, action, identity)
	assessment = evaluateBudgets(config, action, assessment, false)
	event := audit.NewEvent(action, assessment, "")
	if err := (audit.JSONLLogger{Path: config.Audit.Path}).Write(event); err != nil {
		return models.Assessment{}, err
	}
	return assessment, nil
}

func evaluateWithApproval(config policy.Config, action models.Action, identity models.IdentityContext, interactive bool, in io.Reader, out io.Writer, options grantOptions) (models.Assessment, string, error) {
	action, identity = enforce.CanonicalizeIdentity(config, action, identity)
	assessment := enforce.EvaluateWithIdentity(config, action, identity)
	assessment = evaluateBudgets(config, action, assessment, false)
	if assessment.Decision != models.DecisionRequireApproval {
		return assessment, "", nil
	}
	store, err := approval.NewStore(config)
	if err != nil {
		return assessment, "", fmt.Errorf("configure local approvals: %w", err)
	}
	grant, allowed, err := store.IsAllowed(action)
	if err != nil {
		return assessment, "", fmt.Errorf("read local approvals: %w", err)
	}
	if allowed {
		assessment.Decision = models.DecisionAllow
		assessment.DecisionSource = "approval_cache"
		assessment.Reasons = append(assessment.Reasons, fmt.Sprintf("Approved by %s until %s", grant.Approver, grant.ExpiresAt.Format(time.RFC3339)))
		return assessment, "grant:" + grant.ID, nil
	}
	if !interactive {
		return assessment, "pending", nil
	}
	ttl := options.TTL
	if ttl == 0 {
		ttl = config.Approvals.DefaultTTL.Value()
	}
	if ttl <= 0 || ttl > config.Approvals.MaxTTL.Value() {
		return assessment, "", fmt.Errorf("approval TTL must be positive and no greater than %s", config.Approvals.MaxTTL)
	}
	if strings.TrimSpace(options.Approver) == "" {
		return assessment, "", fmt.Errorf("approver identity is required")
	}
	choice, err := approval.Prompt(in, out, action, assessment, ttl)
	if err != nil {
		return assessment, "", err
	}
	switch choice {
	case approval.AllowOnce:
		assessment.Decision = models.DecisionAllow
		assessment.DecisionSource = "operator_approval"
		assessment.Reasons = append(assessment.Reasons, "Allowed once by "+options.Approver)
	case approval.AllowForTTL:
		grant, err := store.Issue(action, options.Approver, ttl)
		if err != nil {
			return assessment, "", fmt.Errorf("save local approval: %w", err)
		}
		assessment.Decision = models.DecisionAllow
		assessment.DecisionSource = "operator_timed_approval"
		assessment.Reasons = append(assessment.Reasons, fmt.Sprintf("Approved by %s until %s", grant.Approver, grant.ExpiresAt.Format(time.RFC3339)))
		return assessment, "grant:" + grant.ID, nil
	case approval.Deny:
		assessment.Decision = models.DecisionBlock
		assessment.DecisionSource = "operator_denial"
		assessment.Reasons = append(assessment.Reasons, "Denied by operator")
	}
	return assessment, string(choice), nil
}

func evaluateBudgets(config policy.Config, action models.Action, assessment models.Assessment, reserve bool) models.Assessment {
	if assessment.Decision == models.DecisionBlock || len(config.Budgets.Rules) == 0 {
		return assessment
	}
	store, err := budget.NewStore(config)
	if err != nil {
		return budget.Apply(assessment, nil, err)
	}
	var statuses []models.BudgetStatus
	if reserve {
		statuses, err = store.Reserve(action)
	} else {
		statuses, err = store.Check(action)
	}
	return budget.Apply(assessment, statuses, err)
}

func defaultApprover() string {
	for _, key := range []string{"LATCH_APPROVER", "USERNAME", "USER"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return "local:" + value
		}
	}
	return "local:operator"
}

func formatGrantTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func loadConfig(path string) (policy.Config, error) {
	if path == "" {
		return applyEnvironmentOverrides(policy.DefaultConfig())
	}
	config, err := policy.Load(path)
	if err != nil {
		return policy.Config{}, fmt.Errorf("load policy: %w", err)
	}
	return applyEnvironmentOverrides(config)
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
	fmt.Fprintf(out, "Source: %s\n", assessment.DecisionSource)
	identityStatus := "unverified"
	if assessment.IdentityVerified {
		identityStatus = "verified"
	}
	agentID := assessment.CanonicalAgentID
	if agentID == "" {
		agentID = action.AgentID
	}
	fmt.Fprintf(out, "Agent: %s (%s via %s)\n", agentID, identityStatus, assessment.IdentitySource)
	if len(assessment.MatchedCapabilities) > 0 {
		fmt.Fprintf(out, "Capabilities: %s\n", strings.Join(assessment.MatchedCapabilities, ", "))
	}
	if len(assessment.Budgets) > 0 {
		fmt.Fprintln(out, "Budgets:")
		for _, status := range assessment.Budgets {
			line := fmt.Sprintf("- %s: %d/%d used in %s", status.RuleID, status.Used, status.Limit, status.Window)
			if status.Exceeded && status.RetryAfter != "" {
				line += " (retry after " + status.RetryAfter + ")"
			}
			fmt.Fprintln(out, line)
		}
	}
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

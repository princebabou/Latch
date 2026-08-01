package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/princebabou/Latch/internal/policy"
)

type mcpLaunchConfig struct {
	Type    string            `json:"type,omitempty"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

type mcpRemoteConfig struct {
	Type    string            `json:"type,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

func integrations(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "Usage: latch integrations mcp|mcp-http [options]")
		return 64
	}
	switch args[0] {
	case "mcp":
		return mcpIntegration(args[1:], out, errOut)
	case "mcp-http":
		return mcpHTTPIntegration(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "Unknown integration %q\n", args[0])
		return 64
	}
}

func mcpIntegration(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("integrations mcp", flag.ContinueOnError)
	fs.SetOutput(errOut)
	client := fs.String("client", "generic", "target client: claude, cursor, vscode, or generic")
	name := fs.String("name", "latch-protected", "MCP server registration name")
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted agent identity")
	latchPath := fs.String("latch", "", "Latch executable; defaults to the current executable")
	directory := fs.String("cwd", "", "working directory for the MCP server")
	outputPath := fs.String("output", "-", "destination JSON path, or - for stdout")
	force := fs.Bool("force", false, "replace an existing destination")
	var environment stringSlice
	fs.Var(&environment, "env", "environment variable in NAME=value form; repeatable")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	serverCommand := fs.Args()
	if len(serverCommand) == 0 {
		fmt.Fprintln(errOut, "an MCP server command is required after --")
		return 64
	}
	clientName := strings.ToLower(strings.TrimSpace(*client))
	switch clientName {
	case "claude", "cursor", "vscode", "generic":
	default:
		fmt.Fprintln(errOut, "--client must be claude, cursor, vscode, or generic")
		return 64
	}
	if strings.TrimSpace(*name) == "" {
		fmt.Fprintln(errOut, "--name is required")
		return 64
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	absoluteConfig, err := filepath.Abs(*configPath)
	if err != nil {
		fmt.Fprintf(errOut, "resolve config path: %v\n", err)
		return 1
	}
	agentID := strings.TrimSpace(*agent)
	if canonical, known := policy.CanonicalAgentID(config, agentID); known {
		agentID = canonical
	}
	if config.Identity.RequireVerified && agentID == "" {
		fmt.Fprintln(errOut, "this policy requires --agent or LATCH_AGENT")
		return 64
	}
	if config.Identity.EnforceCapabilities {
		if _, known := policy.CanonicalAgentID(config, agentID); !known {
			fmt.Fprintf(errOut, "agent %q is not registered for capability enforcement\n", agentID)
			return 64
		}
	}
	resolvedLatch, err := resolveExecutable(*latchPath)
	if err != nil {
		fmt.Fprintf(errOut, "resolve Latch executable: %v\n", err)
		return 1
	}
	childEnvironment, err := parseEnvironment(environment)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}

	proxyArgs := []string{"proxy", "--config", absoluteConfig}
	if agentID != "" {
		proxyArgs = append(proxyArgs, "--agent", agentID)
	}
	if strings.TrimSpace(*directory) != "" {
		absoluteDirectory, err := filepath.Abs(*directory)
		if err != nil {
			fmt.Fprintf(errOut, "resolve working directory: %v\n", err)
			return 1
		}
		proxyArgs = append(proxyArgs, "--cwd", absoluteDirectory)
	}
	proxyArgs = append(proxyArgs, "--", resolveCommandPath(serverCommand[0]))
	proxyArgs = append(proxyArgs, serverCommand[1:]...)
	launch := mcpLaunchConfig{Command: resolvedLatch, Args: proxyArgs, Env: childEnvironment}

	var document any
	switch clientName {
	case "claude", "cursor":
		document = map[string]any{"mcpServers": map[string]any{*name: launch}}
	case "vscode":
		launch.Type = "stdio"
		document = map[string]any{"servers": map[string]any{*name: launch}}
	default:
		document = launch
	}
	return writeIntegrationDocument(document, clientName, *outputPath, *force, out, errOut)
}

func mcpHTTPIntegration(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("integrations mcp-http", flag.ContinueOnError)
	fs.SetOutput(errOut)
	client := fs.String("client", "generic", "target client: claude-code, cursor, vscode, or generic")
	name := fs.String("name", "latch-protected", "MCP server registration name")
	endpoint := fs.String("url", "http://127.0.0.1:7071/mcp", "Latch MCP Streamable HTTP endpoint")
	tokenEnvironment := fs.String("token-env", "LATCH_MCP_TOKEN", "client environment variable containing the proxy token")
	noAuth := fs.Bool("no-auth", false, "generate an authless local configuration")
	outputPath := fs.String("output", "-", "destination JSON path, or - for stdout")
	force := fs.Bool("force", false, "replace an existing destination")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "integrations mcp-http does not accept positional arguments")
		return 64
	}
	clientName := strings.ToLower(strings.TrimSpace(*client))
	switch clientName {
	case "claude-code", "cursor", "vscode", "generic":
	default:
		fmt.Fprintln(errOut, "--client must be claude-code, cursor, vscode, or generic")
		return 64
	}
	if strings.TrimSpace(*name) == "" {
		fmt.Fprintln(errOut, "--name is required")
		return 64
	}
	if !validMCPURL(*endpoint) {
		fmt.Fprintln(errOut, "--url must be an absolute HTTP or HTTPS URL without credentials, query, or fragment")
		return 64
	}
	tokenName := strings.TrimSpace(*tokenEnvironment)
	if !*noAuth && !validEnvironmentName(tokenName) {
		fmt.Fprintln(errOut, "--token-env must be a valid environment variable name")
		return 64
	}
	remote := mcpRemoteConfig{URL: *endpoint}
	var inputs []map[string]any
	if !*noAuth {
		switch clientName {
		case "vscode":
			remote.Headers = map[string]string{"Authorization": "Bearer ${input:latch-mcp-token}"}
			inputs = []map[string]any{{
				"type": "promptString", "id": "latch-mcp-token",
				"description": "Latch MCP bearer token", "password": true,
			}}
		case "cursor":
			remote.Headers = map[string]string{"Authorization": "Bearer ${env:" + tokenName + "}"}
		default:
			remote.Headers = map[string]string{"Authorization": "Bearer ${" + tokenName + "}"}
		}
	}

	var document any
	switch clientName {
	case "vscode":
		remote.Type = "http"
		vscodeDocument := map[string]any{"servers": map[string]any{*name: remote}}
		if len(inputs) > 0 {
			vscodeDocument["inputs"] = inputs
		}
		document = vscodeDocument
	case "cursor":
		// Cursor selects Streamable HTTP from the url field. Omitting type also
		// avoids versions that reject the otherwise equivalent streamable-http alias.
		document = map[string]any{"mcpServers": map[string]any{*name: remote}}
	case "claude-code":
		remote.Type = "http"
		document = map[string]any{"mcpServers": map[string]any{*name: remote}}
	default:
		remote.Type = "http"
		document = remote
	}
	return writeIntegrationDocument(document, clientName, *outputPath, *force, out, errOut)
}

func validMCPURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character == '_' || (index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func writeIntegrationDocument(document any, clientName, outputPath string, force bool, out, errOut io.Writer) int {
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fmt.Fprintf(errOut, "encode integration: %v\n", err)
		return 1
	}
	encoded = append(encoded, '\n')
	if outputPath == "-" {
		_, _ = out.Write(encoded)
		return 0
	}
	absoluteOutput, err := filepath.Abs(outputPath)
	if err != nil {
		fmt.Fprintf(errOut, "resolve output path: %v\n", err)
		return 1
	}
	if err := writePrivateFile(absoluteOutput, encoded, force); err != nil {
		fmt.Fprintf(errOut, "write integration: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Created %s MCP integration at %s\n", clientName, absoluteOutput)
	return 0
}

func resolveExecutable(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		current, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.Abs(current)
	}
	resolved, err := exec.LookPath(value)
	if err != nil {
		return "", err
	}
	return filepath.Abs(resolved)
}

func resolveCommandPath(value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	if strings.ContainsAny(value, `/\`) {
		if absolute, err := filepath.Abs(value); err == nil {
			return absolute
		}
	}
	return value
}

func parseEnvironment(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	values := make(map[string]string, len(raw))
	for _, item := range raw {
		name, value, found := strings.Cut(item, "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			return nil, fmt.Errorf("invalid --env %q; expected NAME=value", item)
		}
		values[name] = value
	}
	return values, nil
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/princebabou/Latch/internal/policy"
)

func TestIdentitiesListShowsTrustConfiguration(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	var out, errOut bytes.Buffer

	code := run([]string{"identities", "list", "--config", configPath}, strings.NewReader(""), &out, &errOut)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
	for _, want := range []string{
		"Require verified: true",
		"Capability enforcement: true",
		"desktop-agent",
		"Claude Desktop",
		"workspace-read",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output %q does not contain %q", out.String(), want)
		}
	}
}

func TestCheckUsesOperatorBoundIdentity(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	var out, errOut bytes.Buffer

	code := run([]string{
		"check", "--config", configPath, "--agent", "Claude Desktop",
		"--tool", "filesystem.read", "--arg", "path=./README.md",
	}, strings.NewReader(""), &out, &errOut)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q, stdout = %q", code, errOut.String(), out.String())
	}
	for _, want := range []string{
		"Decision: ALLOW",
		"Agent: desktop-agent (verified via cli_argument)",
		"Capabilities: workspace-read",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output %q does not contain %q", out.String(), want)
		}
	}
}

func TestRunRejectsSelfAssertedIdentityUnlessOperatorBindsIt(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	inputPath := filepath.Join(t.TempDir(), "actions.jsonl")
	input := `{"agent_id":"desktop-agent","tool":"filesystem.read","arguments":{"path":"./README.md"}}` + "\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	var untrustedOut, untrustedErr bytes.Buffer
	code := run([]string{"run", "--config", configPath, "--input", inputPath}, strings.NewReader(""), &untrustedOut, &untrustedErr)
	if code != 3 {
		t.Fatalf("untrusted exit code = %d, stderr = %q, stdout = %q", code, untrustedErr.String(), untrustedOut.String())
	}
	if !strings.Contains(untrustedOut.String(), "Source: identity_unverified") {
		t.Fatalf("untrusted output = %q", untrustedOut.String())
	}

	var trustedOut, trustedErr bytes.Buffer
	code = run([]string{
		"run", "--config", configPath, "--input", inputPath, "--agent", "desktop-agent",
	}, strings.NewReader(""), &trustedOut, &trustedErr)
	if code != 0 {
		t.Fatalf("trusted exit code = %d, stderr = %q, stdout = %q", code, trustedErr.String(), trustedOut.String())
	}
	if !strings.Contains(trustedOut.String(), "Agent: desktop-agent (verified via cli_argument)") {
		t.Fatalf("trusted output = %q", trustedOut.String())
	}
}

func TestCheckReportsBudgetWithoutConsumingIt(t *testing.T) {
	configPath := writeBudgetTestConfig(t)
	for attempt := 0; attempt < 2; attempt++ {
		var out, errOut bytes.Buffer
		code := run([]string{
			"check", "--config", configPath, "--agent", "Desktop Reader",
			"--tool", "filesystem.read", "--arg", "path=./README.md",
		}, strings.NewReader(""), &out, &errOut)
		if code != 0 {
			t.Fatalf("attempt %d exit code = %d, stderr = %q, stdout = %q", attempt, code, errOut.String(), out.String())
		}
		if !strings.Contains(out.String(), "- read-burst: 0/1 used in 1m0s") {
			t.Fatalf("attempt %d output = %q", attempt, out.String())
		}
	}

	var statusOut, statusErr bytes.Buffer
	code := run([]string{
		"budgets", "status", "--config", configPath, "--agent", "Desktop Reader",
	}, strings.NewReader(""), &statusOut, &statusErr)
	if code != 0 {
		t.Fatalf("status exit code = %d, stderr = %q", code, statusErr.String())
	}
	if !strings.Contains(statusOut.String(), "Agent: desktop-agent") ||
		!strings.Contains(statusOut.String(), "read-burst\t0\t1\t1m0s\t1\t-") {
		t.Fatalf("status output = %q", statusOut.String())
	}
}

func TestInitCreatesValidatedProfilesWithoutOverwriting(t *testing.T) {
	for _, profile := range []string{"balanced", "strict", "developer"} {
		t.Run(profile, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "latch.yaml")
			var out, errOut bytes.Buffer
			code := run([]string{
				"init", "--profile", profile, "--agent", "desktop-agent", "--output", outputPath,
			}, strings.NewReader(""), &out, &errOut)
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
			}
			config, err := policy.Load(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			if !config.Identity.RequireVerified || len(config.Budgets.Rules) != 1 {
				t.Fatalf("generated config = %#v", config)
			}
			if profile == "strict" && !config.Identity.EnforceCapabilities {
				t.Fatal("strict profile did not enable capability enforcement")
			}

			out.Reset()
			errOut.Reset()
			code = run([]string{"init", "--output", outputPath}, strings.NewReader(""), &out, &errOut)
			if code == 0 || !strings.Contains(errOut.String(), "--force") {
				t.Fatalf("overwrite exit code = %d, stderr = %q", code, errOut.String())
			}
		})
	}
}

func TestDoctorUsesEnvironmentDefaultsAndReportsReadiness(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	t.Setenv("LATCH_CONFIG", configPath)
	t.Setenv("LATCH_AGENT", "Claude Desktop")
	var out, errOut bytes.Buffer

	code := run([]string{"doctor", "--json", "--", os.Args[0]}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q, stdout = %q", code, errOut.String(), out.String())
	}
	var report doctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.AgentID != "desktop-agent" {
		t.Fatalf("doctor report = %#v", report)
	}
}

func TestMCPIntegrationGeneratesClientNativeConfiguration(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	for _, client := range []string{"claude", "cursor", "vscode", "generic"} {
		t.Run(client, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run([]string{
				"integrations", "mcp",
				"--client", client,
				"--name", "protected",
				"--config", configPath,
				"--agent", "Claude Desktop",
				"--latch", os.Args[0],
				"--env", "SAFE=value",
				"--", os.Args[0], "--server-flag",
			}, strings.NewReader(""), &out, &errOut)
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
			}
			var document map[string]any
			if err := json.Unmarshal(out.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
			encoded := out.String()
			for _, want := range []string{
				`"proxy"`,
				`"desktop-agent"`,
				filepath.Base(configPath),
				`"SAFE"`,
			} {
				if !strings.Contains(filepath.ToSlash(encoded), want) {
					t.Fatalf("integration output %q does not contain %q", encoded, want)
				}
			}
			if client == "vscode" && !strings.Contains(encoded, `"type": "stdio"`) {
				t.Fatalf("VS Code output = %q", encoded)
			}
			if client == "claude" || client == "cursor" {
				if _, ok := document["mcpServers"]; !ok {
					t.Fatalf("%s output = %#v", client, document)
				}
			}
		})
	}
}

func TestMCPHTTPIntegrationGeneratesSecretSafeClientConfiguration(t *testing.T) {
	for _, client := range []string{"claude-code", "cursor", "vscode", "generic"} {
		t.Run(client, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run([]string{
				"integrations", "mcp-http", "--client", client,
				"--name", "protected", "--url", "https://latch.example/mcp",
				"--token-env", "MY_LATCH_TOKEN",
			}, strings.NewReader(""), &out, &errOut)
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
			}
			if !json.Valid(out.Bytes()) || !strings.Contains(out.String(), "https://latch.example/mcp") || !strings.Contains(out.String(), "Authorization") {
				t.Fatalf("configuration = %s", out.String())
			}
			if strings.Contains(out.String(), "actual-secret") {
				t.Fatalf("configuration embedded a token: %s", out.String())
			}
			switch client {
			case "vscode":
				if !strings.Contains(out.String(), `"password": true`) || !strings.Contains(out.String(), "${input:latch-mcp-token}") {
					t.Fatalf("VS Code configuration = %s", out.String())
				}
			case "cursor":
				if strings.Contains(out.String(), `"type"`) || !strings.Contains(out.String(), "${env:MY_LATCH_TOKEN}") {
					t.Fatalf("Cursor configuration = %s", out.String())
				}
			default:
				if !strings.Contains(out.String(), "${MY_LATCH_TOKEN}") {
					t.Fatalf("configuration = %s", out.String())
				}
			}
		})
	}
}

func TestVersionJSONContainsBuildMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate, oldBuiltBy := version, commit, date, builtBy
	version, commit, date, builtBy = "v1.2.3", "abc123", "2026-07-30T00:00:00Z", "test"
	defer func() { version, commit, date, builtBy = oldVersion, oldCommit, oldDate, oldBuiltBy }()
	var out, errOut bytes.Buffer

	code := run([]string{"version", "--json"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
	var info versionInfo
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Version != "v1.2.3" || info.Commit != "abc123" || info.Platform == "" {
		t.Fatalf("version info = %#v", info)
	}
}

func TestLoadConfigAppliesContainerFriendlyEnvironmentOverrides(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	stateDirectory := t.TempDir()
	auditPath := filepath.Join(stateDirectory, "audit.jsonl")
	approvalPath := filepath.Join(stateDirectory, "approvals.json")
	budgetPath := filepath.Join(stateDirectory, "budgets.json")
	t.Setenv("LATCH_AUDIT_PATH", auditPath)
	t.Setenv("LATCH_APPROVAL_STORE", approvalPath)
	t.Setenv("LATCH_BUDGET_STORE", budgetPath)
	t.Setenv("LATCH_AUDIT_TERMINAL", "false")

	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.Audit.Path != auditPath ||
		config.Approvals.StorePath != approvalPath ||
		config.Budgets.StorePath != budgetPath ||
		config.Audit.Terminal {
		t.Fatalf("environment-adjusted config = %#v", config)
	}
}

func TestDefaultConfigDiscoveryPrefersLocalInitializedPolicy(t *testing.T) {
	t.Setenv("LATCH_CONFIG", "")
	directory := t.TempDir()
	configPath := filepath.Join(directory, defaultConfigPath)
	if err := os.WriteFile(configPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousDirectory) })

	if discovered := defaultConfigFromEnv(); discovered != defaultConfigPath {
		t.Fatalf("default config = %q, want %q", discovered, defaultConfigPath)
	}
}

func writeIdentityTestConfig(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "latch.yaml")
	auditPath := filepath.ToSlash(filepath.Join(tempDir, "audit.jsonl"))
	config := fmt.Sprintf(`version: 1
identity:
  require_verified: true
  enforce_capabilities: true
  agents:
    - id: desktop-agent
      aliases: ["Claude Desktop"]
      capabilities:
        - id: workspace-read
          match:
            tool: filesystem.read
            action: read
            path: "./**"
audit:
  path: %q
  terminal: false
rules: []
`, auditPath)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func writeBudgetTestConfig(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "latch.yaml")
	auditPath := filepath.ToSlash(filepath.Join(tempDir, "audit.jsonl"))
	budgetPath := filepath.ToSlash(filepath.Join(tempDir, "budgets.json"))
	config := fmt.Sprintf(`version: 1
identity:
  require_verified: true
  enforce_capabilities: true
  agents:
    - id: desktop-agent
      aliases: ["Desktop Reader"]
      capabilities:
        - id: workspace-read
          match:
            tool: filesystem.read
            path: "./**"
budgets:
  store_path: %q
  lock_timeout: 1s
  rules:
    - id: read-burst
      match:
        tool: filesystem.read
      max_actions: 1
      window: 1m
audit:
  path: %q
  terminal: false
rules: []
`, budgetPath, auditPath)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

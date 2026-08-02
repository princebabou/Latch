package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

func TestCIGateWritesGitHubContractForAllowedAction(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "github-output")
	summaryPath := filepath.Join(directory, "github-summary")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_OUTPUT", outputPath)
	t.Setenv("GITHUB_STEP_SUMMARY", summaryPath)
	t.Setenv("GITHUB_REPOSITORY", "example/protected-agent")

	var out, errOut bytes.Buffer
	code := run([]string{
		"ci", "--provider", "auto", "--config", configPath,
		"--agent", "Claude Desktop", "--tool", "filesystem.read",
		"--arguments-json", `{"path":"./README.md"}`, "--json",
	}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q, stdout = %q", code, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), "::notice title=Latch policy gate::ALLOW") {
		t.Fatalf("stdout = %q", out.String())
	}
	var response v1.DecisionResponse
	jsonStart := strings.Index(out.String(), "{")
	if jsonStart < 0 || json.Unmarshal([]byte(out.String()[jsonStart:]), &response) != nil {
		t.Fatalf("stdout has no decision response: %q", out.String())
	}
	if response.Decision != models.DecisionAllow || response.FailClosed || response.RequestID == "" {
		t.Fatalf("response = %#v", response)
	}
	outputs, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(outputs), "decision=ALLOW") || !strings.Contains(string(outputs), "allowed=true") {
		t.Fatalf("outputs = %q", outputs)
	}
	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "Latch policy gate") || !strings.Contains(string(summary), "filesystem.read") {
		t.Fatalf("summary = %q", summary)
	}
}

func TestCIGateFailsClosedWhenGitHubReportingIsUnavailable(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_OUTPUT", "")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	var out, errOut bytes.Buffer

	code := run([]string{
		"ci", "--provider", "github", "--config", configPath,
		"--agent", "Claude Desktop", "--tool", "filesystem.read", "--arg", "path=./README.md",
	}, strings.NewReader(""), &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "GITHUB_OUTPUT is unavailable") {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
}

func TestCIGateRejectsAmbiguousArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{
		"ci", "--provider", "generic", "--agent", "github-actions", "--tool", "deployment.apply",
		"--arguments-json", `{"environment":"production"}`, "--arg", "environment=staging",
	}, strings.NewReader(""), &out, &errOut)
	if code != 64 || !strings.Contains(errOut.String(), "defined by both") {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
}

func TestCIGateReadsStrictArgumentsFromEnvironment(t *testing.T) {
	configPath := writeIdentityTestConfig(t)
	t.Setenv("LATCH_TEST_CI_ARGUMENTS", `{"path":"./README.md"}`)
	var out, errOut bytes.Buffer
	code := run([]string{
		"ci", "--provider", "generic", "--config", configPath,
		"--agent", "Claude Desktop", "--tool", "filesystem.read",
		"--arguments-json-env", "LATCH_TEST_CI_ARGUMENTS", "--json",
	}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q, stdout = %q", code, errOut.String(), out.String())
	}
	var response v1.DecisionResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil || response.Decision != models.DecisionAllow {
		t.Fatalf("response = %#v, err = %v", response, err)
	}
}

func TestCIGateReservesBudgetForImmediateExecutionBoundary(t *testing.T) {
	configPath := writeBudgetTestConfig(t)
	for attempt, wantCode := range []int{0, 3} {
		var out, errOut bytes.Buffer
		code := run([]string{
			"ci", "--provider", "generic", "--config", configPath,
			"--agent", "Desktop Reader", "--tool", "filesystem.read", "--arg", "path=./README.md",
		}, strings.NewReader(""), &out, &errOut)
		if code != wantCode {
			t.Fatalf("attempt %d exit code = %d, want %d; stderr = %q, stdout = %q", attempt, code, wantCode, errOut.String(), out.String())
		}
	}
}

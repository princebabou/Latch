package cireport

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/princebabou/Latch/pkg/models"
	"gopkg.in/yaml.v3"
)

func TestResolveProviderDefaultsConservatively(t *testing.T) {
	provider, err := ResolveProvider("auto", Environment{GitHubActions: "true"})
	if err != nil || provider != ProviderGitHub {
		t.Fatalf("provider = %q, err = %v", provider, err)
	}
	provider, err = ResolveProvider("auto", Environment{})
	if err != nil || provider != ProviderGeneric {
		t.Fatalf("provider = %q, err = %v", provider, err)
	}
	if _, err := ResolveProvider("unknown", Environment{}); err == nil {
		t.Fatal("unsupported provider was accepted")
	}
}

func TestWriteGitHubEmitsSafeOutputsAnnotationAndSummary(t *testing.T) {
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "output")
	summaryPath := filepath.Join(directory, "summary")
	var log bytes.Buffer
	result := Result{
		RequestID: "req_12345678",
		Action: models.Action{
			Tool:      "deployment.apply\n::error::injected",
			Operation: "write",
			Resource:  "prod|unsafe",
		},
		Assessment: models.Assessment{
			Decision: models.DecisionBlock, DecisionSource: "policy_block",
			RiskScore: 90, RiskLevel: "CRITICAL", HardDeny: true,
			TriggeredRules: []string{"protect-prod"},
			Reasons:        []string{"No deploy <script>alert(1)</script>\nnext"},
		},
	}
	if err := WriteGitHub(&log, Environment{OutputPath: outputPath, SummaryPath: summaryPath}, result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "\n::error::injected") || strings.Count(log.String(), "\n") != 1 {
		t.Fatalf("annotation was not safely escaped: %q", log.String())
	}
	outputs, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"decision=BLOCK", "allowed=false", "hard_deny=true", `triggered_rules=["protect-prod"]`} {
		if !strings.Contains(string(outputs), want) {
			t.Fatalf("outputs %q do not contain %q", outputs, want)
		}
	}
	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(summary), "<script>") || !strings.Contains(string(summary), "&lt;script&gt;") || !strings.Contains(string(summary), "prod\\|unsafe") {
		t.Fatalf("summary was not safely escaped: %s", summary)
	}
}

func TestWriteGitHubRequiresRunnerFiles(t *testing.T) {
	err := WriteGitHub(&bytes.Buffer{}, Environment{}, Result{})
	if err == nil || !strings.Contains(err.Error(), "GITHUB_OUTPUT") {
		t.Fatalf("error = %v", err)
	}
}

func TestPackagedActionMetadataIsCompositeAndPinned(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
		Outputs map[string]any `yaml:"outputs"`
		Runs    struct {
			Using string           `yaml:"using"`
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(payload, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Runs.Using != "composite" || len(metadata.Runs.Steps) < 4 {
		t.Fatalf("invalid composite action metadata: %#v", metadata.Runs)
	}
	if metadata.Inputs["latch-version"].Default == "latest" || metadata.Inputs["latch-version"].Default == "" {
		t.Fatalf("action release must be pinned, got %q", metadata.Inputs["latch-version"].Default)
	}
	for _, output := range []string{"decision", "allowed", "approval-required", "fail-closed", "triggered-rules"} {
		if _, ok := metadata.Outputs[output]; !ok {
			t.Fatalf("action output %q is missing", output)
		}
	}
}

func TestGitHubWorkflowExamplesAreValidYAML(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, filepath.Join("..", "..", "examples", "github-actions", "policy-gate.yml"))
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var workflow map[string]any
			if err := yaml.Unmarshal(payload, &workflow); err != nil {
				t.Fatal(err)
			}
			if workflow["name"] == nil || workflow["on"] == nil || workflow["jobs"] == nil {
				t.Fatalf("workflow %s is missing name, on, or jobs", path)
			}
		})
	}
}

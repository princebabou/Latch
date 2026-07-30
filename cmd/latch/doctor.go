package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/princebabou/Latch/internal/policy"
)

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type doctorReport struct {
	Ready      bool          `json:"ready"`
	ConfigPath string        `json:"config_path"`
	AgentID    string        `json:"agent_id,omitempty"`
	Version    versionInfo   `json:"version"`
	Checks     []doctorCheck `json:"checks"`
}

func doctor(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted agent identity")
	directory := fs.String("cwd", "", "working directory for the MCP server")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 64
	}

	report := doctorReport{ConfigPath: *configPath, Version: currentVersion()}
	absoluteConfig, err := filepath.Abs(*configPath)
	if err == nil {
		report.ConfigPath = absoluteConfig
	}
	config, loadErr := loadConfig(*configPath)
	if loadErr != nil {
		report.Checks = append(report.Checks, doctorCheck{Name: "policy", Status: "FAIL", Message: loadErr.Error()})
		report.Ready = false
		return writeDoctorReport(report, *jsonOutput, out, errOut)
	}
	report.Checks = append(report.Checks, doctorCheck{
		Name: "policy", Status: "PASS",
		Message: fmt.Sprintf("%d policy rules, %d budget rules", len(config.Rules), len(config.Budgets.Rules)),
	})

	agentID := strings.TrimSpace(*agent)
	if canonical, known := policy.CanonicalAgentID(config, agentID); known {
		agentID = canonical
	}
	report.AgentID = agentID
	switch {
	case config.Identity.RequireVerified && agentID == "":
		report.Checks = append(report.Checks, doctorCheck{Name: "identity", Status: "FAIL", Message: "verified identity is required; pass --agent or set LATCH_AGENT"})
	case config.Identity.EnforceCapabilities:
		if _, known := policy.CanonicalAgentID(config, agentID); !known {
			report.Checks = append(report.Checks, doctorCheck{Name: "identity", Status: "FAIL", Message: fmt.Sprintf("agent %q is not registered for capability enforcement", agentID)})
		} else {
			report.Checks = append(report.Checks, doctorCheck{Name: "identity", Status: "PASS", Message: fmt.Sprintf("verified agent %q has a configured capability ceiling", agentID)})
		}
	case config.Identity.RequireVerified:
		report.Checks = append(report.Checks, doctorCheck{Name: "identity", Status: "PASS", Message: fmt.Sprintf("verified agent %q will be bound by the launcher", agentID)})
	default:
		report.Checks = append(report.Checks, doctorCheck{Name: "identity", Status: "WARN", Message: "identity verification is disabled; enable it before multi-agent or production use"})
	}

	if len(config.Budgets.Rules) == 0 {
		report.Checks = append(report.Checks, doctorCheck{Name: "budgets", Status: "WARN", Message: "no cumulative action budgets are configured"})
	} else {
		report.Checks = append(report.Checks, doctorCheck{Name: "budgets", Status: "PASS", Message: fmt.Sprintf("%d durable per-agent budgets configured", len(config.Budgets.Rules))})
	}

	statePaths := []struct {
		name string
		path string
	}{
		{"audit", config.Audit.Path},
		{"approvals", config.Approvals.StorePath},
		{"budgets", config.Budgets.StorePath},
	}
	seenPaths := make(map[string]string)
	for _, state := range statePaths {
		if state.name == "budgets" && len(config.Budgets.Rules) == 0 {
			continue
		}
		normalized := strings.ToLower(filepath.Clean(state.path))
		if owner, exists := seenPaths[normalized]; exists {
			report.Checks = append(report.Checks, doctorCheck{Name: state.name + "-state", Status: "FAIL", Message: fmt.Sprintf("state path collides with %s: %s", owner, state.path)})
			continue
		}
		seenPaths[normalized] = state.name
		status, message := pathReadiness(state.path)
		report.Checks = append(report.Checks, doctorCheck{Name: state.name + "-state", Status: status, Message: message})
	}

	serverArgs := fs.Args()
	if len(serverArgs) == 0 {
		report.Checks = append(report.Checks, doctorCheck{Name: "mcp-server", Status: "WARN", Message: "no server command supplied; policy and state checks only"})
	} else {
		resolved, lookupErr := exec.LookPath(serverArgs[0])
		if lookupErr != nil {
			report.Checks = append(report.Checks, doctorCheck{Name: "mcp-server", Status: "FAIL", Message: fmt.Sprintf("cannot resolve %q on PATH: %v", serverArgs[0], lookupErr)})
		} else {
			report.Checks = append(report.Checks, doctorCheck{Name: "mcp-server", Status: "PASS", Message: resolved})
		}
	}
	if strings.TrimSpace(*directory) != "" {
		info, statErr := os.Stat(*directory)
		switch {
		case statErr != nil:
			report.Checks = append(report.Checks, doctorCheck{Name: "working-directory", Status: "FAIL", Message: statErr.Error()})
		case !info.IsDir():
			report.Checks = append(report.Checks, doctorCheck{Name: "working-directory", Status: "FAIL", Message: "configured working directory is not a directory"})
		default:
			absolute, _ := filepath.Abs(*directory)
			report.Checks = append(report.Checks, doctorCheck{Name: "working-directory", Status: "PASS", Message: absolute})
		}
	}

	report.Ready = true
	for _, check := range report.Checks {
		if check.Status == "FAIL" {
			report.Ready = false
			break
		}
	}
	return writeDoctorReport(report, *jsonOutput, out, errOut)
}

func pathReadiness(path string) (string, string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "FAIL", "path is empty"
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "FAIL", err.Error()
	}
	if info, statErr := os.Stat(absolute); statErr == nil {
		if info.IsDir() {
			return "FAIL", absolute + " is a directory"
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "WARN", absolute + " exists but is accessible beyond the current user"
		}
		return "PASS", absolute + " exists"
	} else if !os.IsNotExist(statErr) {
		return "FAIL", statErr.Error()
	}

	parent := filepath.Dir(absolute)
	for {
		info, statErr := os.Stat(parent)
		if statErr == nil {
			if !info.IsDir() {
				return "FAIL", parent + " is not a directory"
			}
			if runtime.GOOS != "windows" && info.Mode().Perm()&0o200 == 0 {
				return "FAIL", parent + " is not writable by its owner"
			}
			return "PASS", absolute + " will be created under " + parent
		}
		next := filepath.Dir(parent)
		if next == parent {
			return "FAIL", "no accessible parent directory for " + absolute
		}
		parent = next
	}
}

func writeDoctorReport(report doctorReport, jsonOutput bool, out, errOut io.Writer) int {
	if jsonOutput {
		if err := json.NewEncoder(out).Encode(report); err != nil {
			fmt.Fprintf(errOut, "encode doctor report: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintf(out, "Latch doctor (%s, %s)\n\n", report.Version.Version, report.Version.Platform)
		for _, check := range report.Checks {
			fmt.Fprintf(out, "%-5s %-20s %s\n", check.Status, check.Name, check.Message)
		}
		if report.Ready {
			fmt.Fprintln(out, "\nREADY: Latch can enforce this integration.")
		} else {
			fmt.Fprintln(out, "\nNOT READY: fix the failed checks before launching the integration.")
		}
	}
	if report.Ready {
		return 0
	}
	return 1
}

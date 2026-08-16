// Package risk assigns explainable deterministic risk signals to actions.
package risk

import (
	"strings"

	"github.com/princebabou/Latch/pkg/models"
)

var hardDenySignals = map[string]struct{}{
	"private-key":                 {},
	"environment-file":            {},
	"cloud-credentials":           {},
	"shadow-file":                 {},
	"browser-credentials":         {},
	"password-store":              {},
	"git-credentials":             {},
	"recursive-deletion":          {},
	"remote-script-execution":     {},
	"encoded-script-execution":    {},
	"shell-parse-ambiguity":       {},
	"shell-nesting-limit":         {},
	"security-control-tampering":  {},
	"database-dump":               {},
	"destructive-database-query":  {},
	"unscoped-database-mutation":  {},
	"database-command-execution":  {},
	"database-file-access":        {},
	"database-privilege-change":   {},
	"sql-parse-ambiguity":         {},
	"sql-nesting-limit":           {},
	"secret-in-url":               {},
	"cloud-metadata-access":       {},
	"credential-exfiltration":     {},
	"sensitive-data-exfiltration": {},
	"cleartext-secret-transport":  {},
	"insecure-secret-transport":   {},
	"http-parse-ambiguity":        {},
	"non-http-url-scheme":         {},
}

// Analyze performs local, deterministic inspection. Its detectors are isolated
// by concern so parsers or ML classifiers can be introduced later without
// changing policy evaluation or enforcement.
func Analyze(action models.Action) (int, []models.RiskSignal) {
	collector := newSignalCollector()
	path := lower(firstString(action.Arguments, "path", "file", "filename", "directory", "resource"))

	for _, signal := range pathSignals(path) {
		collector.add(signal.Name, signal.Score, signal.Description)
	}
	collectShellSignals(action, collector)
	collectSQLSignals(action, collector)
	collectHTTPSignals(action, collector)

	if action.Operation == "delete" && !hasShellInput(action.Arguments) {
		collector.add("file-deletion", 40, "File deletion requested")
	}
	if action.Operation == "write" && systemPath(path) {
		collector.add("system-configuration", 45, "System configuration may be modified")
	}
	if action.AgentID == "" {
		collector.add("unknown-agent", 7, "No agent identity was supplied")
	}

	signals := collector.signals()
	score := 0
	for _, signal := range signals {
		score += signal.Score
	}
	if score > 100 {
		score = 100
	}
	return score, signals
}

func level(score int) string {
	switch {
	case score >= 90:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 25:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Level turns a numeric score into a stable presentation value.
func Level(score int) string { return level(score) }

// HardDeny returns the names of signals that ordinary allow rules cannot
// override. Operators must use the explicit break-glass policy mechanism.
func HardDeny(signals []models.RiskSignal) []string {
	var names []string
	for _, signal := range signals {
		if _, protected := hardDenySignals[signal.Name]; protected {
			names = append(names, signal.Name)
		}
	}
	return names
}

func pathSignals(path string) []models.RiskSignal {
	var out []models.RiskSignal
	add := func(name string, score int, description string) {
		out = append(out, models.RiskSignal{Name: name, Score: score, Description: description})
	}
	switch {
	case path == "":
	case strings.Contains(path, ".ssh/id_") || strings.HasSuffix(path, ".pem") || strings.HasSuffix(path, ".key"):
		add("private-key", 80, "Private key material detected")
	case strings.Contains(path, ".env"):
		add("environment-file", 75, "Environment file may contain secrets")
	case strings.Contains(path, ".aws/credentials") || strings.Contains(path, ".config/gcloud") || strings.Contains(path, ".azure"):
		add("cloud-credentials", 80, "Cloud credential location detected")
	case strings.Contains(path, "/etc/shadow"):
		add("shadow-file", 95, "System password hash file detected")
	case strings.Contains(path, "cookies") || strings.Contains(path, "login data"):
		add("browser-credentials", 70, "Browser cookie or credential database detected")
	case strings.Contains(path, "password-store") || strings.Contains(path, ".password-store"):
		add("password-store", 80, "Password store detected")
	case strings.Contains(path, ".bash_history") || strings.Contains(path, ".zsh_history"):
		add("shell-history", 45, "Shell history can contain credentials")
	case strings.Contains(path, ".git-credentials"):
		add("git-credentials", 80, "Git credential file detected")
	}
	if systemPath(path) && !strings.Contains(path, "/etc/shadow") {
		add("sensitive-system-path", 35, "Sensitive system path detected")
	}
	if strings.Contains(path, "/.ssh/") {
		add("sensitive-credential-location", 18, "SSH credential location detected")
	}
	return out
}

func systemPath(path string) bool {
	return strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/usr/") || strings.Contains(path, "/windows/system32/")
}

func firstString(args map[string]any, keys ...string) string {
	value, ok := firstValue(args, keys...)
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

func firstValue(args map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := args[key]; ok {
			return value, true
		}
	}
	for existingKey, value := range args {
		for _, key := range keys {
			if strings.EqualFold(existingKey, key) {
				return value, true
			}
		}
	}
	return nil, false
}

func hasShellInput(arguments map[string]any) bool {
	for _, key := range []string{"command", "cmd", "script", "executable", "program", "binary"} {
		if _, ok := firstValue(arguments, key); ok {
			return true
		}
	}
	return false
}

func lower(value string) string { return strings.ToLower(strings.ReplaceAll(value, "\\", "/")) }

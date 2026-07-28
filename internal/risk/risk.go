// Package risk assigns explainable deterministic risk signals to actions.
package risk

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/latch-security/latch/pkg/models"
)

// Analyze performs local, deterministic inspection. Its detectors are isolated
// by concern so parsers or ML classifiers can be introduced later without
// changing policy evaluation or enforcement.
func Analyze(action models.Action) (int, []models.RiskSignal) {
	signals := []models.RiskSignal{}
	add := func(name string, score int, description string) {
		signals = append(signals, models.RiskSignal{Name: name, Score: score, Description: description})
	}
	path := lower(firstString(action.Arguments, "path", "file", "filename", "directory", "resource"))
	command := firstString(action.Arguments, "command", "cmd", "script")
	query := lower(firstString(action.Arguments, "query", "sql"))
	endpoint := firstString(action.Arguments, "url", "endpoint")

	for _, signal := range pathSignals(path) {
		add(signal.Name, signal.Score, signal.Description)
	}
	for _, signal := range shellSignals(command) {
		add(signal.Name, signal.Score, signal.Description)
	}
	for _, signal := range databaseSignals(query) {
		add(signal.Name, signal.Score, signal.Description)
	}
	for _, signal := range networkSignals(endpoint) {
		add(signal.Name, signal.Score, signal.Description)
	}
	if action.Operation == "delete" && command == "" {
		add("file-deletion", 40, "File deletion requested")
	}
	if action.Operation == "write" && systemPath(path) {
		add("system-configuration", 45, "System configuration may be modified")
	}
	if action.AgentID == "" {
		add("unknown-agent", 7, "No agent identity was supplied")
	}

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

func shellSignals(command string) []models.RiskSignal {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	words := shellWords(command)
	lowerCommand := lower(command)
	var out []models.RiskSignal
	add := func(name string, score int, description string) {
		out = append(out, models.RiskSignal{Name: name, Score: score, Description: description})
	}
	if has(words, "sudo", "su", "doas") {
		add("privilege-escalation", 45, "Privilege escalation command detected")
	}
	if has(words, "rm", "rmdir", "del", "remove-item") {
		if strings.Contains(lowerCommand, "-r") || strings.Contains(lowerCommand, "/s") || strings.Contains(lowerCommand, "recurse") {
			add("recursive-deletion", 90, "Recursive deletion command detected")
		} else {
			add("file-deletion", 55, "Deletion command detected")
		}
	}
	if strings.Contains(lowerCommand, "chmod 777") || strings.Contains(lowerCommand, "icacls") {
		add("unsafe-permissions", 40, "Unsafe permission change detected")
	}
	if (has(words, "curl") || has(words, "wget")) && regexp.MustCompile(`(?i)\|\s*(sh|bash|zsh|powershell|pwsh)\b`).MatchString(command) {
		add("remote-script-execution", 85, "Remote download piped to an interpreter")
	}
	if strings.Contains(lowerCommand, "docker system prune") {
		add("container-prune", 65, "Container data cleanup requested")
	}
	if strings.Contains(lowerCommand, "kubectl delete") {
		add("cluster-deletion", 75, "Kubernetes resource deletion requested")
	}
	if has(words, "env", "printenv", "set") {
		add("environment-enumeration", 25, "Environment enumeration can expose secrets")
	}
	if strings.Contains(lowerCommand, "pg_dump") || strings.Contains(lowerCommand, "mysqldump") {
		add("database-dump", 85, "Database dump command detected")
	}
	return out
}

func databaseSignals(query string) []models.RiskSignal {
	if query == "" {
		return nil
	}
	var out []models.RiskSignal
	if strings.HasPrefix(query, "drop ") || strings.HasPrefix(query, "truncate ") || strings.HasPrefix(query, "delete ") {
		out = append(out, models.RiskSignal{Name: "destructive-database-query", Score: 80, Description: "Destructive database operation detected"})
	}
	if strings.Contains(query, "select *") && !strings.Contains(query, " limit ") {
		out = append(out, models.RiskSignal{Name: "unbounded-database-query", Score: 45, Description: "Unbounded database query detected"})
	}
	if strings.Contains(query, "password") || strings.Contains(query, "token") || strings.Contains(query, "secret") {
		out = append(out, models.RiskSignal{Name: "sensitive-database-column", Score: 40, Description: "Query references sensitive data"})
	}
	return out
}

func networkSignals(endpoint string) []models.RiskSignal {
	if endpoint == "" {
		return nil
	}
	var out []models.RiskSignal
	if parsed, err := url.Parse(endpoint); err == nil && parsed.Hostname() != "" && !strings.EqualFold(parsed.Hostname(), "localhost") {
		out = append(out, models.RiskSignal{Name: "outbound-network", Score: 15, Description: "Outbound network request detected"})
	}
	if regexp.MustCompile(`(?i)(token|secret|api[_-]?key|password)=`).MatchString(endpoint) {
		out = append(out, models.RiskSignal{Name: "secret-in-url", Score: 70, Description: "Potential secret in URL detected"})
	}
	return out
}

func firstString(args map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := args[key].(string); ok {
			return value
		}
	}
	return ""
}
func lower(value string) string { return strings.ToLower(strings.ReplaceAll(value, "\\", "/")) }
func has(words []string, targets ...string) bool {
	for _, word := range words {
		for _, target := range targets {
			if word == target {
				return true
			}
		}
	}
	return false
}

// shellWords is a deliberately small lexical pass, not a shell evaluator. It
// preserves the safety boundary while giving detectors structured command tokens.
func shellWords(command string) []string {
	var words []string
	var current strings.Builder
	var quote rune
	flush := func() {
		if current.Len() > 0 {
			words = append(words, strings.ToLower(current.String()))
			current.Reset()
		}
	}
	for _, ch := range command {
		if quote != 0 {
			if ch == quote {
				quote = 0
			} else {
				current.WriteRune(ch)
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '|' || ch == ';' || ch == '&' {
			flush()
			continue
		}
		current.WriteRune(ch)
	}
	flush()
	return words
}

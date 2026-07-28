// Package policy loads human-readable policy and evaluates normalized actions.
package policy

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/latch-security/latch/pkg/models"
	"gopkg.in/yaml.v3"
)

// StringList accepts either a single YAML string or a YAML list. It keeps
// policies pleasant to write without compromising a typed internal model.
type StringList []string

func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	var single string
	if value.Kind == yaml.ScalarNode {
		if err := value.Decode(&single); err != nil {
			return err
		}
		*s = []string{single}
		return nil
	}
	var many []string
	if err := value.Decode(&many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Config is the complete policy document.
type Config struct {
	Version     int         `yaml:"version"`
	Enforcement Enforcement `yaml:"enforcement"`
	Audit       Audit       `yaml:"audit"`
	Rules       []Rule      `yaml:"rules"`
}

type Enforcement struct {
	ApprovalThreshold int `yaml:"approval_threshold"`
	BlockThreshold    int `yaml:"block_threshold"`
}

type Audit struct {
	Path     string `yaml:"path"`
	Terminal bool   `yaml:"terminal"`
}

type Rule struct {
	ID          string          `yaml:"id"`
	Description string          `yaml:"description"`
	Priority    int             `yaml:"priority"`
	Match       Match           `yaml:"match"`
	Action      models.Decision `yaml:"action"`
}

type Match struct {
	Tool              StringList            `yaml:"tool"`
	Action            StringList            `yaml:"action"`
	Path              StringList            `yaml:"path"`
	Command           StringList            `yaml:"command"`
	Hostname          StringList            `yaml:"hostname"`
	URL               StringList            `yaml:"url"`
	DatabaseOperation StringList            `yaml:"database_operation"`
	HTTPMethod        StringList            `yaml:"http_method"`
	Arguments         map[string]StringList `yaml:"arguments"`
}

// Result contains every matching policy rule, including lower-precedence rules,
// to make a decision traceable during audits and policy simulations.
type Result struct {
	Decision models.Decision
	Rules    []Rule
}

func DefaultConfig() Config {
	return Config{
		Version:     1,
		Enforcement: Enforcement{ApprovalThreshold: 40, BlockThreshold: 90},
		Audit:       Audit{Path: ".latch/audit.jsonl", Terminal: true},
	}
}

// Load parses a YAML policy document, applies safe defaults, and validates it.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read policy file: %w", err)
	}
	config := DefaultConfig()
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse policy file: %w", err)
	}
	for index := range config.Rules {
		config.Rules[index].Action = models.Decision(strings.ToUpper(strings.TrimSpace(string(config.Rules[index].Action))))
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Enforcement.ApprovalThreshold <= 0 {
		return fmt.Errorf("enforcement.approval_threshold must be between 1 and 100")
	}
	if c.Enforcement.BlockThreshold <= 0 || c.Enforcement.BlockThreshold > 100 {
		return fmt.Errorf("enforcement.block_threshold must be between 1 and 100")
	}
	if c.Enforcement.ApprovalThreshold >= c.Enforcement.BlockThreshold {
		return fmt.Errorf("approval threshold must be lower than block threshold")
	}
	ids := map[string]bool{}
	for index, rule := range c.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("rules[%d]: id is required", index)
		}
		if ids[rule.ID] {
			return fmt.Errorf("duplicate policy rule id %q", rule.ID)
		}
		ids[rule.ID] = true
		switch rule.Action {
		case models.DecisionAllow, models.DecisionBlock, models.DecisionRequireApproval:
		default:
			return fmt.Errorf("rule %q: action must be ALLOW, BLOCK, or REQUIRE_APPROVAL", rule.ID)
		}
		if rule.Match.empty() {
			return fmt.Errorf("rule %q: match must contain at least one condition", rule.ID)
		}
	}
	return nil
}

func (m Match) empty() bool {
	return len(m.Tool) == 0 && len(m.Action) == 0 && len(m.Path) == 0 && len(m.Command) == 0 && len(m.Hostname) == 0 && len(m.URL) == 0 && len(m.DatabaseOperation) == 0 && len(m.HTTPMethod) == 0 && len(m.Arguments) == 0
}

// Evaluate uses deny-overrides semantics: a matching BLOCK always wins over a
// matching approval or allow rule, regardless of file order.
func Evaluate(config Config, action models.Action) Result {
	result := Result{Decision: models.DecisionAllow}
	bestPriority := -1 << 30
	for _, rule := range config.Rules {
		if !matches(rule.Match, action) {
			continue
		}
		result.Rules = append(result.Rules, rule)
		if precedence(rule.Action) > precedence(result.Decision) || (precedence(rule.Action) == precedence(result.Decision) && rule.Priority >= bestPriority) {
			result.Decision = rule.Action
			bestPriority = rule.Priority
		}
	}
	return result
}

func precedence(decision models.Decision) int {
	switch decision {
	case models.DecisionBlock:
		return 3
	case models.DecisionRequireApproval:
		return 2
	default:
		return 1
	}
}

func matches(m Match, action models.Action) bool {
	if !anyMatch(m.Tool, action.Tool) || !anyMatch(m.Action, action.Operation) {
		return false
	}
	path := value(action.Arguments, "path", "file", "filename", "directory", "resource")
	if path == "" {
		path = action.Resource
	}
	if !anyMatch(m.Path, path) {
		return false
	}
	if !anyMatch(m.Command, value(action.Arguments, "command", "cmd", "script")) {
		return false
	}
	if !anyMatch(m.URL, value(action.Arguments, "url", "endpoint")) {
		return false
	}
	if !anyMatch(m.Hostname, hostname(value(action.Arguments, "url", "endpoint", "host", "hostname"))) {
		return false
	}
	if !anyMatch(m.DatabaseOperation, databaseOperation(action)) {
		return false
	}
	if !anyMatch(m.HTTPMethod, strings.ToUpper(value(action.Arguments, "method", "http_method"))) {
		return false
	}
	for name, patterns := range m.Arguments {
		actual, exists := action.Arguments[name]
		if !exists || !anyMatch(patterns, fmt.Sprint(actual)) {
			return false
		}
	}
	return true
}

func value(arguments map[string]any, keys ...string) string {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if actual, ok := arguments[key]; ok {
			return fmt.Sprint(actual)
		}
	}
	return ""
}

func hostname(raw string) string {
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return strings.Split(raw, "/")[0]
}

func databaseOperation(action models.Action) string {
	if explicit := value(action.Arguments, "operation", "database_operation"); explicit != "" {
		return strings.ToUpper(explicit)
	}
	query := strings.TrimSpace(value(action.Arguments, "query", "sql"))
	if fields := strings.Fields(query); len(fields) > 0 {
		return strings.ToUpper(fields[0])
	}
	return ""
}

func anyMatch(patterns StringList, actual string) bool {
	if len(patterns) == 0 {
		return true
	}
	if actual == "" {
		return false
	}
	for _, pattern := range patterns {
		if glob(pattern, actual) {
			return true
		}
	}
	return false
}

// glob supports ** across path segments and works consistently on Windows and Unix.
func glob(pattern, actual string) bool {
	pattern = expandHome(strings.ReplaceAll(pattern, "\\", "/"))
	actual = expandHome(strings.ReplaceAll(actual, "\\", "/"))
	var out strings.Builder
	out.WriteString("(?i)^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					out.WriteString("(?:.*/)?")
					i++
				} else {
					out.WriteString(".*")
				}
			} else {
				out.WriteString("[^/]*")
			}
		case '?':
			out.WriteString("[^/]")
		default:
			out.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	out.WriteString("$")
	re, err := regexp.Compile(out.String())
	return err == nil && re.MatchString(actual)
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return strings.Replace(path, "~", strings.ReplaceAll(home, "\\", "/"), 1)
		}
	}
	return path
}

// Package policy loads human-readable policy and evaluates normalized actions.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/risk"
	"github.com/princebabou/Latch/pkg/models"
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
	Version     int            `yaml:"version"`
	Enforcement Enforcement    `yaml:"enforcement"`
	Identity    IdentityConfig `yaml:"identity"`
	Budgets     BudgetConfig   `yaml:"budgets"`
	Approvals   ApprovalConfig `yaml:"approvals"`
	Audit       Audit          `yaml:"audit"`
	Rules       []Rule         `yaml:"rules"`
}

// Duration is a YAML-friendly time.Duration with strict human-readable input.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("duration must be a string such as 15m or 24h: %w", err)
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Value() time.Duration { return time.Duration(d) }
func (d Duration) String() string       { return time.Duration(d).String() }

type ApprovalConfig struct {
	StorePath   string   `yaml:"store_path"`
	DefaultTTL  Duration `yaml:"default_ttl"`
	MaxTTL      Duration `yaml:"max_ttl"`
	LockTimeout Duration `yaml:"lock_timeout"`
}

// BudgetConfig defines durable, per-agent limits for cumulative action volume.
// Budget rules are security ceilings and cannot be bypassed by policy allows,
// approvals, or unsafe overrides.
type BudgetConfig struct {
	StorePath   string       `yaml:"store_path" json:"-"`
	LockTimeout Duration     `yaml:"lock_timeout" json:"-"`
	Rules       []BudgetRule `yaml:"rules" json:"rules,omitempty"`
}

type BudgetRule struct {
	ID          string   `yaml:"id" json:"id"`
	Description string   `yaml:"description" json:"description,omitempty"`
	Match       Match    `yaml:"match" json:"match"`
	MaxActions  int      `yaml:"max_actions" json:"max_actions"`
	Window      Duration `yaml:"window" json:"window"`
}

// IdentityConfig controls whether a transport-authenticated agent identity is
// mandatory and whether registered capabilities form a maximum permission set.
type IdentityConfig struct {
	RequireVerified     bool            `yaml:"require_verified" json:"require_verified"`
	EnforceCapabilities bool            `yaml:"enforce_capabilities" json:"enforce_capabilities"`
	Agents              []AgentIdentity `yaml:"agents" json:"agents,omitempty"`
}

type AgentIdentity struct {
	ID           string       `yaml:"id" json:"id"`
	Aliases      StringList   `yaml:"aliases" json:"aliases,omitempty"`
	Capabilities []Capability `yaml:"capabilities" json:"capabilities,omitempty"`
}

type Capability struct {
	ID          string `yaml:"id" json:"id"`
	Description string `yaml:"description" json:"description,omitempty"`
	Match       Match  `yaml:"match" json:"match"`
}

type Enforcement struct {
	ApprovalThreshold    int  `yaml:"approval_threshold"`
	BlockThreshold       int  `yaml:"block_threshold"`
	AllowUnsafeOverrides bool `yaml:"allow_unsafe_overrides"`
}

type Audit struct {
	Path     string `yaml:"path"`
	Terminal bool   `yaml:"terminal"`
}

type Rule struct {
	ID             string          `yaml:"id"`
	Description    string          `yaml:"description"`
	Priority       int             `yaml:"priority"`
	UnsafeOverride bool            `yaml:"unsafe_override"`
	Match          Match           `yaml:"match"`
	Action         models.Decision `yaml:"action"`
}

type Match struct {
	Tool              StringList            `yaml:"tool" json:"tool,omitempty"`
	Action            StringList            `yaml:"action" json:"action,omitempty"`
	Path              StringList            `yaml:"path" json:"path,omitempty"`
	Command           StringList            `yaml:"command" json:"command,omitempty"`
	Hostname          StringList            `yaml:"hostname" json:"hostname,omitempty"`
	URL               StringList            `yaml:"url" json:"url,omitempty"`
	DatabaseOperation StringList            `yaml:"database_operation" json:"database_operation,omitempty"`
	HTTPMethod        StringList            `yaml:"http_method" json:"http_method,omitempty"`
	Arguments         map[string]StringList `yaml:"arguments" json:"arguments,omitempty"`
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
		Approvals: ApprovalConfig{
			StorePath: ".latch/approvals.json", DefaultTTL: Duration(15 * time.Minute),
			MaxTTL: Duration(24 * time.Hour), LockTimeout: Duration(2 * time.Second),
		},
		Budgets: BudgetConfig{
			StorePath: ".latch/budgets.json", LockTimeout: Duration(2 * time.Second),
		},
		Audit: Audit{Path: ".latch/audit.jsonl", Terminal: true},
	}
}

// Load parses a YAML policy document, applies safe defaults, and validates it.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read policy file: %w", err)
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve policy path: %w", err)
	}
	return Parse(data, filepath.Dir(absolutePath))
}

// Parse decodes one strict YAML policy document, applies safe defaults,
// resolves operational paths against baseDirectory, and validates the result.
// Unknown fields and extra YAML documents are rejected so policy typos cannot
// silently weaken an intended control.
func Parse(data []byte, baseDirectory string) (Config, error) {
	config := DefaultConfig()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		if err == io.EOF {
			return Config{}, fmt.Errorf("parse policy file: policy document is empty")
		}
		return Config{}, fmt.Errorf("parse policy file: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("parse policy file: multiple YAML documents are not supported")
		}
		return Config{}, fmt.Errorf("parse policy file: %w", err)
	}
	for index := range config.Rules {
		config.Rules[index].Action = models.Decision(strings.ToUpper(strings.TrimSpace(string(config.Rules[index].Action))))
	}
	if strings.TrimSpace(baseDirectory) == "" {
		baseDirectory = "."
	}
	absoluteDirectory, err := filepath.Abs(baseDirectory)
	if err != nil {
		return Config{}, fmt.Errorf("resolve policy base directory: %w", err)
	}
	config.Approvals.StorePath = resolveOperationalPath(absoluteDirectory, config.Approvals.StorePath)
	config.Budgets.StorePath = resolveOperationalPath(absoluteDirectory, config.Budgets.StorePath)
	config.Audit.Path = resolveOperationalPath(absoluteDirectory, config.Audit.Path)
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func resolveOperationalPath(baseDirectory, path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(baseDirectory, path))
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
	if strings.TrimSpace(c.Approvals.StorePath) == "" {
		return fmt.Errorf("approvals.store_path is required")
	}
	if c.Approvals.DefaultTTL.Value() <= 0 {
		return fmt.Errorf("approvals.default_ttl must be positive")
	}
	if c.Approvals.MaxTTL.Value() <= 0 || c.Approvals.DefaultTTL.Value() > c.Approvals.MaxTTL.Value() {
		return fmt.Errorf("approvals.max_ttl must be positive and at least default_ttl")
	}
	if c.Approvals.LockTimeout.Value() <= 0 {
		return fmt.Errorf("approvals.lock_timeout must be positive")
	}
	if err := c.Budgets.validate(); err != nil {
		return err
	}
	if len(c.Budgets.Rules) > 0 && !c.Identity.RequireVerified {
		return fmt.Errorf("budgets require identity.require_verified: true")
	}
	if err := c.Identity.validate(); err != nil {
		return err
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
		if rule.UnsafeOverride {
			if rule.Action != models.DecisionAllow {
				return fmt.Errorf("rule %q: unsafe_override is valid only for ALLOW rules", rule.ID)
			}
			if !c.Enforcement.AllowUnsafeOverrides {
				return fmt.Errorf("rule %q: unsafe_override requires enforcement.allow_unsafe_overrides: true", rule.ID)
			}
			if strings.TrimSpace(rule.Description) == "" {
				return fmt.Errorf("rule %q: unsafe_override requires a description", rule.ID)
			}
			if !rule.Match.resourceSpecific() {
				return fmt.Errorf("rule %q: unsafe_override must match a path, command, URL, hostname, database operation, HTTP method, or argument", rule.ID)
			}
		}
	}
	return nil
}

func (budgets BudgetConfig) validate() error {
	const (
		maxBudgetRules   = 128
		maxBudgetActions = 10_000
		maxBudgetWindow  = 365 * 24 * time.Hour
	)
	if len(budgets.Rules) == 0 {
		return nil
	}
	if len(budgets.Rules) > maxBudgetRules {
		return fmt.Errorf("budgets.rules cannot contain more than %d rules", maxBudgetRules)
	}
	if strings.TrimSpace(budgets.StorePath) == "" {
		return fmt.Errorf("budgets.store_path is required when budget rules are configured")
	}
	if budgets.LockTimeout.Value() <= 0 {
		return fmt.Errorf("budgets.lock_timeout must be positive when budget rules are configured")
	}
	ids := make(map[string]bool)
	for index, rule := range budgets.Rules {
		ruleID := strings.TrimSpace(rule.ID)
		if ruleID == "" {
			return fmt.Errorf("budgets.rules[%d]: id is required", index)
		}
		if ruleID != rule.ID {
			return fmt.Errorf("budget rule id %q cannot contain leading or trailing whitespace", rule.ID)
		}
		key := strings.ToLower(ruleID)
		if ids[key] {
			return fmt.Errorf("duplicate budget rule id %q", ruleID)
		}
		ids[key] = true
		if rule.Match.empty() {
			return fmt.Errorf("budget rule %q must contain at least one match condition", ruleID)
		}
		if rule.MaxActions <= 0 {
			return fmt.Errorf("budget rule %q max_actions must be positive", ruleID)
		}
		if rule.MaxActions > maxBudgetActions {
			return fmt.Errorf("budget rule %q max_actions cannot exceed %d", ruleID, maxBudgetActions)
		}
		if rule.Window.Value() <= 0 {
			return fmt.Errorf("budget rule %q window must be positive", ruleID)
		}
		if rule.Window.Value() > maxBudgetWindow {
			return fmt.Errorf("budget rule %q window cannot exceed %s", ruleID, maxBudgetWindow)
		}
	}
	return nil
}

func (identity IdentityConfig) validate() error {
	if identity.EnforceCapabilities && !identity.RequireVerified {
		return fmt.Errorf("identity.enforce_capabilities requires identity.require_verified: true")
	}
	if identity.EnforceCapabilities && len(identity.Agents) == 0 {
		return fmt.Errorf("identity.enforce_capabilities requires at least one registered agent")
	}
	principals := make(map[string]string)
	for agentIndex, agent := range identity.Agents {
		agentID := strings.TrimSpace(agent.ID)
		if agentID == "" {
			return fmt.Errorf("identity.agents[%d]: id is required", agentIndex)
		}
		if agentID != agent.ID {
			return fmt.Errorf("identity agent id %q cannot contain leading or trailing whitespace", agent.ID)
		}
		for _, principal := range append([]string{agentID}, agent.Aliases...) {
			trimmedPrincipal := strings.TrimSpace(principal)
			if trimmedPrincipal == "" {
				return fmt.Errorf("identity agent %q: aliases cannot be empty", agentID)
			}
			if trimmedPrincipal != principal {
				return fmt.Errorf("identity principal %q cannot contain leading or trailing whitespace", principal)
			}
			key := strings.ToLower(trimmedPrincipal)
			if owner, exists := principals[key]; exists {
				return fmt.Errorf("identity principal %q is assigned to both %q and %q", principal, owner, agentID)
			}
			principals[key] = agentID
		}
		capabilityIDs := make(map[string]bool)
		for capabilityIndex, capability := range agent.Capabilities {
			capabilityID := strings.TrimSpace(capability.ID)
			if capabilityID == "" {
				return fmt.Errorf("identity agent %q capabilities[%d]: id is required", agentID, capabilityIndex)
			}
			if capabilityID != capability.ID {
				return fmt.Errorf("identity agent %q capability id %q cannot contain leading or trailing whitespace", agentID, capability.ID)
			}
			key := strings.ToLower(capabilityID)
			if capabilityIDs[key] {
				return fmt.Errorf("identity agent %q has duplicate capability id %q", agentID, capabilityID)
			}
			capabilityIDs[key] = true
			if capability.Match.empty() {
				return fmt.Errorf("identity agent %q capability %q must contain at least one match condition", agentID, capabilityID)
			}
		}
	}
	return nil
}

// Digest identifies the security semantics that an approval grant was issued
// against. Operational output and storage locations are intentionally excluded.
func Digest(config Config) (string, error) {
	material := struct {
		Version     int
		Enforcement Enforcement
		Identity    IdentityConfig
		Budgets     []BudgetRule
		Approvals   struct {
			DefaultTTL Duration
			MaxTTL     Duration
		}
		Rules []Rule
	}{
		Version:     config.Version,
		Enforcement: config.Enforcement,
		Identity:    config.Identity,
		Budgets:     config.Budgets.Rules,
		Rules:       config.Rules,
	}
	material.Approvals.DefaultTTL = config.Approvals.DefaultTTL
	material.Approvals.MaxTTL = config.Approvals.MaxTTL
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode policy digest: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

type IdentityResult struct {
	Allowed             bool
	DecisionSource      string
	Reason              string
	CanonicalAgentID    string
	KnownAgent          bool
	MatchedCapabilities []string
}

// AuthorizeIdentity evaluates transport trust and the configured capability
// ceiling independently from ordinary allow, approval, and break-glass rules.
func AuthorizeIdentity(config Config, identity models.IdentityContext, action models.Action) IdentityResult {
	identity.ID = strings.TrimSpace(identity.ID)
	actionClaim := strings.TrimSpace(action.AgentID)
	if identity.ID == "" {
		identity.ID = actionClaim
	}
	if identity.Source == "" {
		identity.Source = "self_asserted"
	}

	canonicalIdentity, knownIdentity := canonicalAgent(config.Identity, identity.ID)
	canonicalAction, _ := canonicalAgent(config.Identity, actionClaim)
	if canonicalIdentity == "" {
		canonicalIdentity = identity.ID
	}
	if canonicalAction == "" {
		canonicalAction = actionClaim
	}
	result := IdentityResult{
		Allowed:          true,
		CanonicalAgentID: canonicalIdentity,
		KnownAgent:       knownIdentity,
	}

	if identity.ID != "" && actionClaim != "" && !strings.EqualFold(canonicalIdentity, canonicalAction) {
		result.Allowed = false
		result.DecisionSource = "identity_mismatch"
		result.Reason = fmt.Sprintf("Trusted identity %q does not match action claim %q", identity.ID, actionClaim)
		return result
	}
	if config.Identity.RequireVerified && !identity.Verified {
		result.Allowed = false
		result.DecisionSource = "identity_unverified"
		result.Reason = fmt.Sprintf("Agent identity %q was self-asserted by %s", identity.ID, identity.Source)
		return result
	}

	if knownIdentity {
		for _, agent := range config.Identity.Agents {
			if !strings.EqualFold(agent.ID, canonicalIdentity) {
				continue
			}
			for _, capability := range agent.Capabilities {
				if matches(capability.Match, action) {
					result.MatchedCapabilities = append(result.MatchedCapabilities, capability.ID)
				}
			}
			break
		}
	}
	if config.Identity.EnforceCapabilities {
		if !knownIdentity {
			result.Allowed = false
			result.DecisionSource = "identity_unknown"
			result.Reason = fmt.Sprintf("Agent identity %q is not registered", identity.ID)
			return result
		}
		if len(result.MatchedCapabilities) == 0 {
			result.Allowed = false
			result.DecisionSource = "capability_denied"
			result.Reason = fmt.Sprintf("Agent %q has no capability matching this action", canonicalIdentity)
			return result
		}
	}
	return result
}

func canonicalAgent(config IdentityConfig, claim string) (string, bool) {
	claim = strings.TrimSpace(claim)
	if claim == "" {
		return "", false
	}
	for _, agent := range config.Agents {
		if strings.EqualFold(agent.ID, claim) {
			return agent.ID, true
		}
		for _, alias := range agent.Aliases {
			if strings.EqualFold(alias, claim) {
				return agent.ID, true
			}
		}
	}
	return claim, false
}

// CanonicalAgentID resolves a configured ID or alias to the stable agent ID.
func CanonicalAgentID(config Config, claim string) (string, bool) {
	return canonicalAgent(config.Identity, claim)
}

func (m Match) resourceSpecific() bool {
	return len(m.Path) > 0 || len(m.Command) > 0 || len(m.Hostname) > 0 || len(m.URL) > 0 || len(m.DatabaseOperation) > 0 || len(m.HTTPMethod) > 0 || len(m.Arguments) > 0
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
	if !anyMatchAny(m.DatabaseOperation, databaseOperations(action)) {
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

// MatchAction exposes the same typed matcher used by policies and capabilities
// to other enforcement controls such as cumulative action budgets.
func MatchAction(match Match, action models.Action) bool {
	return matches(match, action)
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
	for existingKey, actual := range arguments {
		for _, key := range keys {
			if strings.EqualFold(existingKey, key) {
				return fmt.Sprint(actual)
			}
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

func databaseOperations(action models.Action) []string {
	if explicit := value(action.Arguments, "operation", "database_operation"); explicit != "" {
		return []string{strings.ToUpper(explicit)}
	}
	query := strings.TrimSpace(value(action.Arguments, "query", "sql"))
	return risk.DatabaseOperations(query)
}

func anyMatchAny(patterns StringList, actualValues []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, actual := range actualValues {
		if anyMatch(patterns, actual) {
			return true
		}
	}
	return false
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

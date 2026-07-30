// Package budget enforces durable, per-agent action limits.
package budget

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	storeVersion     = 1
	maxStoreFileSize = 4 << 20
)

// Store serializes reservations through an operating-system lock and replaces
// its state atomically. Every counter is scoped to one policy digest, agent,
// budget rule, and rolling time window.
type Store struct {
	Path         string
	PolicyDigest string
	Rules        []policy.BudgetRule
	LockTimeout  time.Duration
	Now          func() time.Time
}

type occurrence struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type entry struct {
	PolicyDigest string       `json:"policy_digest"`
	AgentID      string       `json:"agent_id"`
	RuleID       string       `json:"rule_id"`
	Occurrences  []occurrence `json:"occurrences"`
}

type storeDocument struct {
	Version int     `json:"version"`
	Entries []entry `json:"entries"`
}

// NewStore binds cumulative action state to the security semantics of a loaded
// policy. Operational paths and lock timeouts are intentionally not digested.
func NewStore(config policy.Config) (Store, error) {
	digest, err := policy.Digest(config)
	if err != nil {
		return Store{}, err
	}
	store := Store{
		Path:         config.Budgets.StorePath,
		PolicyDigest: digest,
		Rules:        append([]policy.BudgetRule(nil), config.Budgets.Rules...),
		LockTimeout:  config.Budgets.LockTimeout.Value(),
	}
	if len(store.Rules) > 0 {
		if err := store.validate(); err != nil {
			return Store{}, err
		}
	}
	return store, nil
}

// Check reports whether an action is currently within every matching budget
// without consuming capacity.
func (s Store) Check(action models.Action) ([]models.BudgetStatus, error) {
	return s.evaluate(action.AgentID, matchingRules(s.Rules, action), false)
}

// Reserve atomically consumes one unit from every matching budget. If any
// budget is exhausted, no budget is changed.
func (s Store) Reserve(action models.Action) ([]models.BudgetStatus, error) {
	return s.evaluate(action.AgentID, matchingRules(s.Rules, action), true)
}

// Status reports active usage for every configured budget rule for one agent.
func (s Store) Status(agentID string) ([]models.BudgetStatus, error) {
	return s.evaluate(agentID, s.Rules, false)
}

// Apply adds budget state to an assessment and turns exhaustion or unavailable
// state into a non-bypassable block.
func Apply(assessment models.Assessment, statuses []models.BudgetStatus, storeErr error) models.Assessment {
	assessment.Budgets = statuses
	if assessment.Decision == models.DecisionBlock {
		return assessment
	}
	if storeErr != nil {
		assessment.Decision = models.DecisionBlock
		assessment.DecisionSource = "budget_store_failure"
		assessment.Reasons = append(assessment.Reasons, "Cumulative action state could not be verified safely")
		return assessment
	}
	for _, status := range statuses {
		if !status.Exceeded {
			continue
		}
		assessment.Decision = models.DecisionBlock
		assessment.DecisionSource = "budget_exhausted"
		reason := fmt.Sprintf("Action budget %q is exhausted (%d actions per %s)", status.RuleID, status.Limit, status.Window)
		if status.RetryAfter != "" {
			reason += "; retry after " + status.RetryAfter
		}
		assessment.Reasons = append(assessment.Reasons, reason)
	}
	return assessment
}

func (s Store) evaluate(agentID string, rules []policy.BudgetRule, reserve bool) ([]models.BudgetStatus, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, fmt.Errorf("budgeted action requires a verified agent identity")
	}

	var statuses []models.BudgetStatus
	err := s.withLock(func() error {
		document, err := s.readDocument()
		if err != nil {
			return err
		}
		now := s.now()
		pruned := pruneExpired(&document, now)
		statuses = make([]models.BudgetStatus, 0, len(rules))
		exceeded := false
		for _, rule := range rules {
			active := activeEntry(&document, s.PolicyDigest, agentID, rule.ID)
			used := len(active.Occurrences)
			status := statusFor(rule, active.Occurrences, used, now)
			statuses = append(statuses, status)
			exceeded = exceeded || status.Exceeded
		}
		if reserve && !exceeded {
			for index, rule := range rules {
				active := ensureEntry(&document, s.PolicyDigest, agentID, rule.ID)
				active.Occurrences = append(active.Occurrences, occurrence{ExpiresAt: now.Add(rule.Window.Value())})
				statuses[index] = statusFor(rule, active.Occurrences, len(active.Occurrences), now)
				// The reservation that fills the last available slot is valid.
				// Exceeded describes whether this action was denied, not whether
				// the next action would be denied.
				statuses[index].Exceeded = false
				statuses[index].RetryAfter = ""
			}
		}
		if pruned || (reserve && !exceeded) {
			return s.writeDocument(document)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(statuses, func(i, j int) bool { return statuses[i].RuleID < statuses[j].RuleID })
	return statuses, nil
}

func matchingRules(rules []policy.BudgetRule, action models.Action) []policy.BudgetRule {
	matched := make([]policy.BudgetRule, 0, len(rules))
	for _, rule := range rules {
		if policy.MatchAction(rule.Match, action) {
			matched = append(matched, rule)
		}
	}
	return matched
}

func statusFor(rule policy.BudgetRule, occurrences []occurrence, used int, now time.Time) models.BudgetStatus {
	remaining := rule.MaxActions - used
	if remaining < 0 {
		remaining = 0
	}
	status := models.BudgetStatus{
		RuleID:      rule.ID,
		Description: rule.Description,
		Limit:       rule.MaxActions,
		Used:        used,
		Remaining:   remaining,
		Window:      rule.Window.String(),
		Exceeded:    used >= rule.MaxActions,
	}
	if status.Exceeded && len(occurrences) > 0 {
		retry := occurrences[0].ExpiresAt.Sub(now)
		for _, item := range occurrences[1:] {
			if candidate := item.ExpiresAt.Sub(now); candidate < retry {
				retry = candidate
			}
		}
		if retry < 0 {
			retry = 0
		}
		status.RetryAfter = retry.Round(time.Millisecond).String()
	}
	return status
}

func activeEntry(document *storeDocument, digest, agentID, ruleID string) *entry {
	for index := range document.Entries {
		current := &document.Entries[index]
		if current.PolicyDigest == digest && strings.EqualFold(current.AgentID, agentID) && strings.EqualFold(current.RuleID, ruleID) {
			return current
		}
	}
	return &entry{}
}

func ensureEntry(document *storeDocument, digest, agentID, ruleID string) *entry {
	if current := activeEntry(document, digest, agentID, ruleID); current.PolicyDigest != "" {
		return current
	}
	document.Entries = append(document.Entries, entry{
		PolicyDigest: digest,
		AgentID:      agentID,
		RuleID:       ruleID,
	})
	return &document.Entries[len(document.Entries)-1]
}

func pruneExpired(document *storeDocument, now time.Time) bool {
	changed := false
	entries := document.Entries[:0]
	for _, current := range document.Entries {
		active := current.Occurrences[:0]
		for _, item := range current.Occurrences {
			if now.Before(item.ExpiresAt) {
				active = append(active, item)
			} else {
				changed = true
			}
		}
		current.Occurrences = active
		if len(active) > 0 {
			entries = append(entries, current)
		} else {
			changed = true
		}
	}
	document.Entries = entries
	return changed
}

func (s Store) validate() error {
	if strings.TrimSpace(s.Path) == "" {
		return fmt.Errorf("budget store path is required")
	}
	if strings.TrimSpace(s.PolicyDigest) == "" {
		return fmt.Errorf("budget store must be bound to a policy digest")
	}
	if s.LockTimeout <= 0 {
		return fmt.Errorf("budget lock timeout must be positive")
	}
	return nil
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Store) withLock(operation func() error) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return fmt.Errorf("create budget directory: %w", err)
	}
	lockPath := s.Path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open budget lock: %w", err)
	}
	defer lock.Close()
	if err := lock.Chmod(0o600); err != nil {
		return fmt.Errorf("secure budget lock: %w", err)
	}

	deadline := time.Now().Add(s.LockTimeout)
	for {
		locked, err := tryLockFile(lock)
		if err != nil {
			return fmt.Errorf("acquire budget lock: %w", err)
		}
		if locked {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("budget store lock timed out after %s", s.LockTimeout)
		}
		time.Sleep(25 * time.Millisecond)
	}

	operationErr := operation()
	unlockErr := unlockFile(lock)
	if operationErr != nil {
		return operationErr
	}
	if unlockErr != nil {
		return fmt.Errorf("release budget lock: %w", unlockErr)
	}
	return nil
}

func (s Store) readDocument() (storeDocument, error) {
	file, err := os.Open(s.Path)
	if os.IsNotExist(err) {
		return storeDocument{Version: storeVersion}, nil
	}
	if err != nil {
		return storeDocument{}, fmt.Errorf("open budget store: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStoreFileSize+1))
	if err != nil {
		return storeDocument{}, fmt.Errorf("read budget store: %w", err)
	}
	if len(data) > maxStoreFileSize {
		return storeDocument{}, fmt.Errorf("budget store exceeds %d bytes", maxStoreFileSize)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return storeDocument{Version: storeVersion}, nil
	}
	var document storeDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return storeDocument{}, fmt.Errorf("parse budget store: %w", err)
	}
	if document.Version != storeVersion {
		return storeDocument{}, fmt.Errorf("unsupported budget store version %d", document.Version)
	}
	keys := make(map[string]bool)
	for index, current := range document.Entries {
		if strings.TrimSpace(current.PolicyDigest) == "" || strings.TrimSpace(current.AgentID) == "" || strings.TrimSpace(current.RuleID) == "" {
			return storeDocument{}, fmt.Errorf("budget store entry %d is incomplete", index)
		}
		key := current.PolicyDigest + "\x00" + strings.ToLower(current.AgentID) + "\x00" + strings.ToLower(current.RuleID)
		if keys[key] {
			return storeDocument{}, fmt.Errorf("budget store entry %d duplicates an existing counter", index)
		}
		keys[key] = true
		for occurrenceIndex, item := range current.Occurrences {
			if item.ExpiresAt.IsZero() {
				return storeDocument{}, fmt.Errorf("budget store entry %d occurrence %d has no expiry", index, occurrenceIndex)
			}
		}
	}
	return document, nil
}

func (s Store) writeDocument(document storeDocument) error {
	document.Version = storeVersion
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode budget store: %w", err)
	}
	if len(data) > maxStoreFileSize {
		return fmt.Errorf("budget store would exceed %d bytes", maxStoreFileSize)
	}
	directory := filepath.Dir(s.Path)
	temp, err := os.CreateTemp(directory, "."+filepath.Base(s.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create budget temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure budget temporary file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write budget temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync budget temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close budget temporary file: %w", err)
	}
	if err := os.Rename(tempPath, s.Path); err != nil {
		return fmt.Errorf("replace budget store atomically: %w", err)
	}
	return nil
}

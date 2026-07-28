// Package approval contains the intentionally explicit human-in-the-loop gate.
package approval

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/latch-security/latch/pkg/models"
)

type Choice string

const (
	AllowOnce   Choice = "allow_once"
	Deny        Choice = "denied"
	AlwaysAllow Choice = "allow_always"
)

// Prompt never executes an action. It only returns the operator's decision so
// an integration can decide whether to forward the already-approved request.
func Prompt(in io.Reader, out io.Writer, action models.Action, assessment models.Assessment) (Choice, error) {
	fmt.Fprintln(out, "\nLATCH SECURITY APPROVAL")
	fmt.Fprintf(out, "\nAgent: %s\nTool: %s\nResource: %s\nRisk: %s (%d/100)\n", fallback(action.AgentID, "unknown"), action.Tool, fallback(action.Resource, "(none)"), assessment.RiskLevel, assessment.RiskScore)
	if command, ok := action.Arguments["command"].(string); ok {
		fmt.Fprintf(out, "\nCommand:\n%s\n", command)
	}
	if len(assessment.Reasons) > 0 {
		fmt.Fprintln(out, "\nReasons:")
		for _, reason := range assessment.Reasons {
			fmt.Fprintf(out, "- %s\n", reason)
		}
	}
	fmt.Fprint(out, "\n[a] Allow once  [d] Deny  [A] Always allow this exact action: ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && len(strings.TrimSpace(line)) == 0 {
		return Deny, fmt.Errorf("read approval: %w", err)
	}
	switch strings.TrimSpace(line) {
	case "a":
		return AllowOnce, nil
	case "A":
		return AlwaysAllow, nil
	default:
		return Deny, nil
	}
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

// Store is a deliberately narrow local approval cache. "Always" means the
// same normalized action and arguments, never a broad tool-level exception.
type Store struct{ Path string }
type record struct {
	Fingerprint string    `json:"fingerprint"`
	ApprovedAt  time.Time `json:"approved_at"`
}

func (s Store) IsAllowed(action models.Action) (bool, error) {
	records, err := s.read()
	if err != nil {
		return false, err
	}
	fingerprint, err := Fingerprint(action)
	if err != nil {
		return false, err
	}
	for _, existing := range records {
		if existing.Fingerprint == fingerprint {
			return true, nil
		}
	}
	return false, nil
}

func (s Store) Allow(action models.Action) error {
	records, err := s.read()
	if err != nil {
		return err
	}
	fingerprint, err := Fingerprint(action)
	if err != nil {
		return err
	}
	for _, existing := range records {
		if existing.Fingerprint == fingerprint {
			return nil
		}
	}
	records = append(records, record{Fingerprint: fingerprint, ApprovedAt: time.Now().UTC()})
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, data, 0o600)
}

func (s Store) read() ([]record, error) {
	data, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse approval store: %w", err)
	}
	return records, nil
}

func Fingerprint(action models.Action) (string, error) {
	data, err := json.Marshal(struct {
		AgentID, Tool, Operation, Resource string
		Arguments                          map[string]any
	}{action.AgentID, action.Tool, action.Operation, action.Resource, action.Arguments})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

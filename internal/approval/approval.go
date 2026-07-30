// Package approval contains Latch's explicit human-in-the-loop gate and
// durable, policy-bound approval grants.
package approval

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	storeVersion     = 2
	maxStoreFileSize = 16 << 20
)

var ErrGrantNotFound = errors.New("approval grant not found")

type Choice string

const (
	AllowOnce   Choice = "allow_once"
	Deny        Choice = "denied"
	AllowForTTL Choice = "allow_ttl"
)

// Prompt never executes an action. It only returns the operator's decision so
// an integration can decide whether to forward the already-approved request.
func Prompt(in io.Reader, out io.Writer, action models.Action, assessment models.Assessment, ttl time.Duration) (Choice, error) {
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
	fmt.Fprintf(out, "\n[a] Allow once  [d] Deny  [t] Allow this exact action for %s: ", ttl)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && len(strings.TrimSpace(line)) == 0 {
		return Deny, fmt.Errorf("read approval: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "a":
		return AllowOnce, nil
	case "t":
		return AllowForTTL, nil
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

// Store serializes access through a lock file and replaces its JSON document
// atomically. Grants are valid only for the configured policy digest/version.
type Store struct {
	Path          string
	PolicyDigest  string
	PolicyVersion int
	DefaultTTL    time.Duration
	MaxTTL        time.Duration
	LockTimeout   time.Duration
	Now           func() time.Time
}

// Grant is a time-bound approval for one exact normalized action.
type Grant struct {
	ID             string     `json:"id"`
	Fingerprint    string     `json:"fingerprint"`
	PolicyDigest   string     `json:"policy_digest"`
	PolicyVersion  int        `json:"policy_version"`
	Approver       string     `json:"approver"`
	AgentID        string     `json:"agent_id"`
	Tool           string     `json:"tool"`
	Operation      string     `json:"operation"`
	Resource       string     `json:"resource,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevokedBy      string     `json:"revoked_by,omitempty"`
	RevocationNote string     `json:"revocation_note,omitempty"`
	Legacy         bool       `json:"legacy,omitempty"`
	Status         string     `json:"status,omitempty"`
}

type storeDocument struct {
	Version int     `json:"version"`
	Grants  []Grant `json:"grants"`
}

type legacyRecord struct {
	Fingerprint string    `json:"fingerprint"`
	ApprovedAt  time.Time `json:"approved_at"`
}

// NewStore binds a store to the security semantics of one loaded policy.
func NewStore(config policy.Config) (Store, error) {
	digest, err := policy.Digest(config)
	if err != nil {
		return Store{}, err
	}
	store := Store{
		Path:          config.Approvals.StorePath,
		PolicyDigest:  digest,
		PolicyVersion: config.Version,
		DefaultTTL:    config.Approvals.DefaultTTL.Value(),
		MaxTTL:        config.Approvals.MaxTTL.Value(),
		LockTimeout:   config.Approvals.LockTimeout.Value(),
	}
	if err := store.validate(); err != nil {
		return Store{}, err
	}
	return store, nil
}

// IsAllowed returns the newest active grant for an exact action.
func (s Store) IsAllowed(action models.Action) (Grant, bool, error) {
	s = s.defaults()
	if err := s.validate(); err != nil {
		return Grant{}, false, err
	}
	fingerprint, err := Fingerprint(action)
	if err != nil {
		return Grant{}, false, err
	}
	var matched Grant
	err = s.withLock(func() error {
		document, err := s.readDocument()
		if err != nil {
			return err
		}
		now := s.now()
		for index := len(document.Grants) - 1; index >= 0; index-- {
			grant := document.Grants[index]
			if grant.Fingerprint == fingerprint && s.status(grant, now) == "active" {
				matched = grant
				matched.Status = "active"
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return Grant{}, false, err
	}
	return matched, matched.ID != "", nil
}

// Issue creates a new grant. Any active grant for the same exact action and
// policy is revoked as superseded so the history remains explicit.
func (s Store) Issue(action models.Action, approver string, ttl time.Duration) (Grant, error) {
	s = s.defaults()
	if err := s.validate(); err != nil {
		return Grant{}, err
	}
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return Grant{}, fmt.Errorf("approver identity is required")
	}
	if ttl == 0 {
		ttl = s.DefaultTTL
	}
	if ttl <= 0 || ttl > s.MaxTTL {
		return Grant{}, fmt.Errorf("approval TTL must be positive and no greater than %s", s.MaxTTL)
	}
	fingerprint, err := Fingerprint(action)
	if err != nil {
		return Grant{}, err
	}
	id, err := randomID()
	if err != nil {
		return Grant{}, fmt.Errorf("generate approval id: %w", err)
	}
	now := s.now()
	safeAction := audit.RedactAction(action)
	grant := Grant{
		ID: id, Fingerprint: fingerprint, PolicyDigest: s.PolicyDigest, PolicyVersion: s.PolicyVersion,
		Approver: approver, AgentID: action.AgentID, Tool: action.Tool, Operation: action.Operation,
		Resource: safeAction.Resource, CreatedAt: now, ExpiresAt: now.Add(ttl), Status: "active",
	}
	err = s.withLock(func() error {
		document, err := s.readDocument()
		if err != nil {
			return err
		}
		for index := range document.Grants {
			existing := &document.Grants[index]
			if existing.Fingerprint == fingerprint && s.status(*existing, now) == "active" {
				revokedAt := now
				existing.RevokedAt = &revokedAt
				existing.RevokedBy = approver
				existing.RevocationNote = "superseded by grant " + id
			}
		}
		document.Grants = append(document.Grants, grant)
		return s.writeDocument(document)
	})
	if err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// List returns grants newest-first with a status relative to the current policy.
func (s Store) List() ([]Grant, error) {
	s = s.defaults()
	if err := s.validate(); err != nil {
		return nil, err
	}
	grants := make([]Grant, 0)
	err := s.withLock(func() error {
		document, err := s.readDocument()
		if err != nil {
			return err
		}
		now := s.now()
		grants = append(grants, document.Grants...)
		for index := range grants {
			grants[index].Status = s.status(grants[index], now)
		}
		sort.SliceStable(grants, func(i, j int) bool { return grants[i].CreatedAt.After(grants[j].CreatedAt) })
		return nil
	})
	return grants, err
}

// Revoke invalidates one grant while retaining its audit history.
func (s Store) Revoke(id, revokedBy, reason string) (Grant, error) {
	s = s.defaults()
	if err := s.validate(); err != nil {
		return Grant{}, err
	}
	id, revokedBy, reason = strings.TrimSpace(id), strings.TrimSpace(revokedBy), strings.TrimSpace(reason)
	if id == "" {
		return Grant{}, fmt.Errorf("approval id is required")
	}
	if revokedBy == "" {
		return Grant{}, fmt.Errorf("revoker identity is required")
	}
	if reason == "" {
		return Grant{}, fmt.Errorf("revocation reason is required")
	}
	var revoked Grant
	err := s.withLock(func() error {
		document, err := s.readDocument()
		if err != nil {
			return err
		}
		now := s.now()
		for index := range document.Grants {
			if document.Grants[index].ID != id {
				continue
			}
			grant := &document.Grants[index]
			if grant.RevokedAt == nil {
				revokedAt := now
				grant.RevokedAt = &revokedAt
				grant.RevokedBy = revokedBy
				grant.RevocationNote = reason
				if err := s.writeDocument(document); err != nil {
					return err
				}
			}
			revoked = *grant
			revoked.Status = "revoked"
			return nil
		}
		return ErrGrantNotFound
	})
	return revoked, err
}

// Prune removes inactive records. Revocation history is retained until this
// explicit maintenance operation is requested.
func (s Store) Prune() (int, error) {
	s = s.defaults()
	if err := s.validate(); err != nil {
		return 0, err
	}
	removed := 0
	err := s.withLock(func() error {
		document, err := s.readDocument()
		if err != nil {
			return err
		}
		now := s.now()
		active := document.Grants[:0]
		for _, grant := range document.Grants {
			if s.status(grant, now) == "active" {
				active = append(active, grant)
			} else {
				removed++
			}
		}
		document.Grants = active
		if removed == 0 {
			return nil
		}
		return s.writeDocument(document)
	})
	return removed, err
}

func (s Store) status(grant Grant, now time.Time) string {
	switch {
	case grant.Legacy || grant.PolicyDigest == "" || grant.ExpiresAt.IsZero():
		return "legacy_invalid"
	case grant.RevokedAt != nil:
		return "revoked"
	case grant.PolicyDigest != s.PolicyDigest || grant.PolicyVersion != s.PolicyVersion:
		return "policy_mismatch"
	case !now.Before(grant.ExpiresAt):
		return "expired"
	default:
		return "active"
	}
}

func (s Store) defaults() Store {
	if s.DefaultTTL <= 0 {
		s.DefaultTTL = 15 * time.Minute
	}
	if s.MaxTTL <= 0 {
		s.MaxTTL = 24 * time.Hour
	}
	if s.LockTimeout <= 0 {
		s.LockTimeout = 2 * time.Second
	}
	return s
}

func (s Store) validate() error {
	if strings.TrimSpace(s.Path) == "" {
		return fmt.Errorf("approval store path is required")
	}
	if strings.TrimSpace(s.PolicyDigest) == "" || s.PolicyVersion <= 0 {
		return fmt.Errorf("approval store must be bound to a policy digest and version")
	}
	if s.DefaultTTL <= 0 || s.MaxTTL <= 0 || s.DefaultTTL > s.MaxTTL {
		return fmt.Errorf("invalid approval TTL configuration")
	}
	if s.LockTimeout <= 0 {
		return fmt.Errorf("invalid approval lock configuration")
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
		return fmt.Errorf("create approval directory: %w", err)
	}
	lockPath := s.Path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open approval lock: %w", err)
	}
	defer lock.Close()
	if err := lock.Chmod(0o600); err != nil {
		return fmt.Errorf("secure approval lock: %w", err)
	}

	deadline := time.Now().Add(s.LockTimeout)
	for {
		locked, err := tryLockFile(lock)
		if err != nil {
			return fmt.Errorf("acquire approval lock: %w", err)
		}
		if locked {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("approval store lock timed out after %s", s.LockTimeout)
		}
		time.Sleep(25 * time.Millisecond)
	}

	operationErr := operation()
	unlockErr := unlockFile(lock)
	if operationErr != nil {
		return operationErr
	}
	if unlockErr != nil {
		return fmt.Errorf("release approval lock: %w", unlockErr)
	}
	return nil
}

func (s Store) readDocument() (storeDocument, error) {
	file, err := os.Open(s.Path)
	if os.IsNotExist(err) {
		return storeDocument{Version: storeVersion}, nil
	}
	if err != nil {
		return storeDocument{}, fmt.Errorf("open approval store: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStoreFileSize+1))
	if err != nil {
		return storeDocument{}, fmt.Errorf("read approval store: %w", err)
	}
	if len(data) > maxStoreFileSize {
		return storeDocument{}, fmt.Errorf("approval store exceeds %d bytes", maxStoreFileSize)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return storeDocument{Version: storeVersion}, nil
	}
	if trimmed[0] == '[' {
		var legacy []legacyRecord
		if err := json.Unmarshal(trimmed, &legacy); err != nil {
			return storeDocument{}, fmt.Errorf("parse legacy approval store: %w", err)
		}
		document := storeDocument{Version: storeVersion}
		for _, old := range legacy {
			id := "legacy"
			if len(old.Fingerprint) >= 12 {
				id += "-" + old.Fingerprint[:12]
			}
			document.Grants = append(document.Grants, Grant{
				ID: id, Fingerprint: old.Fingerprint, CreatedAt: old.ApprovedAt.UTC(), Legacy: true,
			})
		}
		return document, nil
	}
	var document storeDocument
	if err := json.Unmarshal(trimmed, &document); err != nil {
		return storeDocument{}, fmt.Errorf("parse approval store: %w", err)
	}
	if document.Version != storeVersion {
		return storeDocument{}, fmt.Errorf("unsupported approval store version %d", document.Version)
	}
	return document, nil
}

func (s Store) writeDocument(document storeDocument) error {
	document.Version = storeVersion
	for index := range document.Grants {
		document.Grants[index].Status = ""
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode approval store: %w", err)
	}
	directory := filepath.Dir(s.Path)
	temp, err := os.CreateTemp(directory, "."+filepath.Base(s.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create approval temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure approval temporary file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write approval temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync approval temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close approval temporary file: %w", err)
	}
	if err := os.Rename(tempPath, s.Path); err != nil {
		return fmt.Errorf("replace approval store atomically: %w", err)
	}
	return nil
}

func randomID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
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

package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

func TestIssueAndUseExactPolicyBoundGrant(t *testing.T) {
	store, clock := testStore(t)
	action := testAction("npm test")
	grant, err := store.Issue(action, "alice@example.com", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Approver != "alice@example.com" || !grant.ExpiresAt.Equal(clock.Add(10*time.Minute)) {
		t.Fatalf("grant = %#v", grant)
	}
	matched, allowed, err := store.IsAllowed(action)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed || matched.ID != grant.ID {
		t.Fatalf("matched = %#v, allowed = %v", matched, allowed)
	}
	if _, allowed, err := store.IsAllowed(testAction("npm run build")); err != nil || allowed {
		t.Fatalf("different action allowed = %v, error = %v", allowed, err)
	}
}

func TestGrantExpires(t *testing.T) {
	store, clock := testStore(t)
	action := testAction("npm test")
	if _, err := store.Issue(action, "alice", time.Minute); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(2 * time.Minute)
	if _, allowed, err := store.IsAllowed(action); err != nil || allowed {
		t.Fatalf("expired grant allowed = %v, error = %v", allowed, err)
	}
	grants, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Status != "expired" {
		t.Fatalf("grants = %#v", grants)
	}
}

func TestPolicyChangeInvalidatesGrant(t *testing.T) {
	store, _ := testStore(t)
	action := testAction("npm test")
	if _, err := store.Issue(action, "alice", time.Minute); err != nil {
		t.Fatal(err)
	}

	changed := policy.DefaultConfig()
	changed.Approvals.StorePath = store.Path
	changed.Rules = []policy.Rule{{
		ID: "changed-policy", Action: models.DecisionRequireApproval,
		Match: policy.Match{Tool: policy.StringList{"shell.exec"}},
	}}
	changedStore, err := NewStore(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, allowed, err := changedStore.IsAllowed(action); err != nil || allowed {
		t.Fatalf("policy-mismatched grant allowed = %v, error = %v", allowed, err)
	}
	grants, err := changedStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if grants[0].Status != "policy_mismatch" {
		t.Fatalf("status = %q, want policy_mismatch", grants[0].Status)
	}
}

func TestRevokeRetainsHistoryAndDisablesGrant(t *testing.T) {
	store, _ := testStore(t)
	action := testAction("npm test")
	grant, err := store.Issue(action, "alice", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.Revoke(grant.ID, "security-admin", "incident response")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != "revoked" || revoked.RevokedBy != "security-admin" || revoked.RevocationNote != "incident response" {
		t.Fatalf("revoked grant = %#v", revoked)
	}
	if _, allowed, err := store.IsAllowed(action); err != nil || allowed {
		t.Fatalf("revoked grant allowed = %v, error = %v", allowed, err)
	}
	grants, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Status != "revoked" {
		t.Fatalf("grants = %#v", grants)
	}
}

func TestIssueRejectsMissingApproverAndExcessiveTTL(t *testing.T) {
	store, _ := testStore(t)
	if _, err := store.Issue(testAction("npm test"), "", time.Minute); err == nil {
		t.Fatal("expected missing approver error")
	}
	if _, err := store.Issue(testAction("npm test"), "alice", store.MaxTTL+time.Second); err == nil {
		t.Fatal("expected maximum TTL error")
	}
}

func TestLegacyPermanentEntriesAreNeverTrusted(t *testing.T) {
	store, clock := testStore(t)
	action := testAction("npm test")
	fingerprint, err := Fingerprint(action)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal([]legacyRecord{{Fingerprint: fingerprint, ApprovedAt: *clock}})
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, allowed, err := store.IsAllowed(action); err != nil || allowed {
		t.Fatalf("legacy grant allowed = %v, error = %v", allowed, err)
	}
	grants, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Status != "legacy_invalid" {
		t.Fatalf("grants = %#v", grants)
	}
}

func TestConcurrentIssuesPreserveEveryGrant(t *testing.T) {
	store, _ := testStore(t)
	const count = 12
	var wait sync.WaitGroup
	errorsFound := make(chan error, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := store.Issue(testAction(fmt.Sprintf("npm test --shard=%d", index)), fmt.Sprintf("operator-%d", index), time.Minute)
			errorsFound <- err
		}(index)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	grants, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != count {
		t.Fatalf("stored %d grants, want %d", len(grants), count)
	}
	for _, grant := range grants {
		if grant.Status != "active" {
			t.Fatalf("grant %s status = %s", grant.ID, grant.Status)
		}
	}
}

func TestLockTimeoutFailsClosed(t *testing.T) {
	store, _ := testStore(t)
	store.LockTimeout = 50 * time.Millisecond
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(store.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	locked, err := tryLockFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("test could not acquire approval lock")
	}
	defer unlockFile(lock)
	if _, _, err := store.IsAllowed(testAction("npm test")); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v, want lock timeout", err)
	}
}

func TestPruneRemovesOnlyInactiveGrants(t *testing.T) {
	store, clock := testStore(t)
	active, err := store.Issue(testAction("npm test"), "alice", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	expiring, err := store.Issue(testAction("npm lint"), "bob", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(active.ID, "admin", "no longer needed"); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(2 * time.Minute)
	removed, err := store.Prune()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	grants, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("remaining grants = %#v (expired id %s)", grants, expiring.ID)
	}
	encoded, err := json.Marshal(grants)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "[]" {
		t.Fatalf("empty grants JSON = %s, want []", encoded)
	}
}

func testStore(t *testing.T) (Store, *time.Time) {
	t.Helper()
	config := policy.DefaultConfig()
	config.Approvals.StorePath = filepath.Join(t.TempDir(), "approvals.json")
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return clock }
	return store, &clock
}

func testAction(command string) models.Action {
	return models.Action{
		AgentID: "test-agent", Tool: "shell.exec", Operation: "execute", Resource: command,
		Arguments: map[string]any{"command": command},
	}
}

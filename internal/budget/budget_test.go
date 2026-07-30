package budget

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/princebabou/Latch/internal/policy"
	"github.com/princebabou/Latch/pkg/models"
)

func TestStoreReservesThroughLimitAndExpiresRollingWindow(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now, []policy.BudgetRule{testRule("reads", 2, time.Minute)})
	action := testAction("reader")

	statuses, err := store.Check(action)
	assertStatus(t, statuses, err, 0, 2, false)
	statuses, err = store.Reserve(action)
	assertStatus(t, statuses, err, 1, 1, false)
	statuses, err = store.Reserve(action)
	assertStatus(t, statuses, err, 2, 0, false)

	statuses, err = store.Check(action)
	assertStatus(t, statuses, err, 2, 0, true)
	statuses, err = store.Reserve(action)
	assertStatus(t, statuses, err, 2, 0, true)

	now = now.Add(time.Minute)
	statuses, err = store.Check(action)
	assertStatus(t, statuses, err, 0, 2, false)
}

func TestStoreReservationIsAtomicAcrossMatchingRules(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now, []policy.BudgetRule{
		testRule("strict", 1, time.Minute),
		testRule("loose", 2, time.Minute),
	})
	action := testAction("reader")

	if _, err := store.Reserve(action); err != nil {
		t.Fatal(err)
	}
	statuses, err := store.Reserve(action)
	if err != nil {
		t.Fatal(err)
	}
	if !statusByID(t, statuses, "strict").Exceeded {
		t.Fatal("strict budget should reject the second reservation")
	}
	loose := statusByID(t, statuses, "loose")
	if loose.Used != 1 {
		t.Fatalf("loose budget used = %d, want 1 after atomic denial", loose.Used)
	}
}

func TestConcurrentReservationsNeverOversubscribe(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now, []policy.BudgetRule{testRule("reads", 5, time.Minute)})
	action := testAction("reader")
	var allowed atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses, err := store.Reserve(action)
			if err != nil {
				failures.Add(1)
				return
			}
			if len(statuses) == 1 && !statuses[0].Exceeded {
				allowed.Add(1)
			}
		}()
	}
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("reservation failures = %d", failures.Load())
	}
	if allowed.Load() != 5 {
		t.Fatalf("allowed reservations = %d, want exactly 5", allowed.Load())
	}
	statuses, err := store.Status("reader")
	assertStatus(t, statuses, err, 5, 0, true)
}

func TestCountersAreScopedByCanonicalAgentAndPolicyDigest(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now, []policy.BudgetRule{testRule("reads", 1, time.Minute)})
	if _, err := store.Reserve(testAction("reader")); err != nil {
		t.Fatal(err)
	}
	reader, err := store.Check(testAction("reader"))
	assertStatus(t, reader, err, 1, 0, true)

	writer, err := store.Reserve(testAction("writer"))
	assertStatus(t, writer, err, 1, 0, false)

	changedPolicy := store
	changedPolicy.PolicyDigest = "different-policy-digest"
	freshScope, err := changedPolicy.Reserve(testAction("reader"))
	assertStatus(t, freshScope, err, 1, 0, false)
}

func TestStoreFailsClosedOnCorruptState(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now, []policy.BudgetRule{testRule("reads", 1, time.Minute)})
	if err := os.WriteFile(store.Path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Check(testAction("reader")); err == nil {
		t.Fatal("corrupt budget state was accepted")
	}
	assessment := Apply(models.Assessment{Decision: models.DecisionAllow}, nil, os.ErrInvalid)
	if assessment.Decision != models.DecisionBlock || assessment.DecisionSource != "budget_store_failure" {
		t.Fatalf("assessment = %#v", assessment)
	}
}

func TestNonMatchingActionDoesNotTouchStore(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, &now, []policy.BudgetRule{testRule("reads", 1, time.Minute)})
	statuses, err := store.Reserve(models.Action{AgentID: "reader", Tool: "shell.exec"})
	if err != nil || len(statuses) != 0 {
		t.Fatalf("statuses = %#v, err = %v", statuses, err)
	}
	if _, err := os.Stat(store.Path); !os.IsNotExist(err) {
		t.Fatalf("non-matching action created budget state: %v", err)
	}
}

func newTestStore(t *testing.T, now *time.Time, rules []policy.BudgetRule) Store {
	t.Helper()
	config := policy.DefaultConfig()
	config.Identity.RequireVerified = true
	config.Budgets.StorePath = filepath.Join(t.TempDir(), "budgets.json")
	config.Budgets.LockTimeout = policy.Duration(10 * time.Second)
	config.Budgets.Rules = rules
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(config)
	if err != nil {
		t.Fatal(err)
	}
	store.Now = func() time.Time { return *now }
	return store
}

func testRule(id string, limit int, window time.Duration) policy.BudgetRule {
	return policy.BudgetRule{
		ID: id,
		Match: policy.Match{
			Tool: policy.StringList{"filesystem.read"},
		},
		MaxActions: limit,
		Window:     policy.Duration(window),
	}
}

func testAction(agentID string) models.Action {
	return models.Action{AgentID: agentID, Tool: "filesystem.read", Operation: "read"}
}

func assertStatus(t *testing.T, statuses []models.BudgetStatus, err error, used, remaining int, exceeded bool) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses = %#v", statuses)
	}
	status := statuses[0]
	if status.Used != used || status.Remaining != remaining || status.Exceeded != exceeded {
		t.Fatalf("status = %#v, want used=%d remaining=%d exceeded=%t", status, used, remaining, exceeded)
	}
}

func statusByID(t *testing.T, statuses []models.BudgetStatus, id string) models.BudgetStatus {
	t.Helper()
	for _, status := range statuses {
		if status.RuleID == id {
			return status
		}
	}
	t.Fatalf("budget %q missing from %#v", id, statuses)
	return models.BudgetStatus{}
}

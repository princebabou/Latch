package risk

import (
	"testing"

	"github.com/latch-security/latch/pkg/models"
)

func TestDangerousShellCommandIsCritical(t *testing.T) {
	score, signals := Analyze(models.Action{AgentID: "test", Tool: "shell.exec", Operation: "execute", Arguments: map[string]any{"command": "rm -rf ./data"}})
	if score < 90 {
		t.Fatalf("score = %d, want at least 90", score)
	}
	if len(signals) == 0 || signals[0].Name != "recursive-deletion" {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestSecretInURLRaisesRisk(t *testing.T) {
	score, _ := Analyze(models.Action{AgentID: "test", Tool: "http.request", Operation: "network", Arguments: map[string]any{"url": "https://example.test/export?token=abc"}})
	if score < 70 {
		t.Fatalf("score = %d, want at least 70", score)
	}
}

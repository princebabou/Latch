package policy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBudgetValidationRequiresVerifiedIdentityAndStrictRules(t *testing.T) {
	validRule := BudgetRule{
		ID: "reads",
		Match: Match{
			Tool: StringList{"filesystem.read"},
		},
		MaxActions: 10,
		Window:     Duration(time.Minute),
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "unverified identity",
			mutate: func(config *Config) {
				config.Budgets.Rules = []BudgetRule{validRule}
			},
			want: "identity.require_verified",
		},
		{
			name: "empty match",
			mutate: func(config *Config) {
				config.Identity.RequireVerified = true
				rule := validRule
				rule.Match = Match{}
				config.Budgets.Rules = []BudgetRule{rule}
			},
			want: "match",
		},
		{
			name: "zero maximum",
			mutate: func(config *Config) {
				config.Identity.RequireVerified = true
				rule := validRule
				rule.MaxActions = 0
				config.Budgets.Rules = []BudgetRule{rule}
			},
			want: "max_actions",
		},
		{
			name: "zero window",
			mutate: func(config *Config) {
				config.Identity.RequireVerified = true
				rule := validRule
				rule.Window = 0
				config.Budgets.Rules = []BudgetRule{rule}
			},
			want: "window",
		},
		{
			name: "duplicate id",
			mutate: func(config *Config) {
				config.Identity.RequireVerified = true
				duplicate := validRule
				duplicate.ID = "READS"
				config.Budgets.Rules = []BudgetRule{validRule, duplicate}
			},
			want: "duplicate",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig()
			test.mutate(&config)
			err := config.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestBudgetSecurityChangesDigestButStoreLocationDoesNot(t *testing.T) {
	base := DefaultConfig()
	base.Identity.RequireVerified = true
	base.Budgets.Rules = []BudgetRule{{
		ID: "reads",
		Match: Match{
			Tool: StringList{"filesystem.read"},
		},
		MaxActions: 10,
		Window:     Duration(time.Minute),
	}}
	first, err := Digest(base)
	if err != nil {
		t.Fatal(err)
	}

	moved := base
	moved.Budgets.StorePath = filepath.Join("other", "budgets.json")
	second, err := Digest(moved)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("operational budget store location changed policy digest")
	}

	tighter := base
	tighter.Budgets.Rules = append([]BudgetRule(nil), base.Budgets.Rules...)
	tighter.Budgets.Rules[0].MaxActions = 9
	third, err := Digest(tighter)
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("budget security change did not alter policy digest")
	}
}

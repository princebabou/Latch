package policy

import (
	"strings"
	"testing"

	"github.com/princebabou/Latch/pkg/models"
)

func TestAuthorizeIdentityResolvesAliasAndMatchesCapabilities(t *testing.T) {
	config := identityTestConfig()
	action := models.Action{
		AgentID: "Claude Desktop", Tool: "filesystem.read", Operation: "read",
		Arguments: map[string]any{"path": "./README.md"},
	}
	result := AuthorizeIdentity(config, models.IdentityContext{
		ID: "Claude Desktop", Verified: true, Source: "operator_config",
	}, action)
	if !result.Allowed || result.CanonicalAgentID != "desktop-agent" {
		t.Fatalf("identity result = %#v", result)
	}
	if len(result.MatchedCapabilities) != 1 || result.MatchedCapabilities[0] != "workspace-read" {
		t.Fatalf("capabilities = %#v", result.MatchedCapabilities)
	}
}

func TestAuthorizeIdentityRejectsUnverifiedUnknownAndOutOfCapability(t *testing.T) {
	config := identityTestConfig()
	tests := []struct {
		name     string
		identity models.IdentityContext
		action   models.Action
		source   string
	}{
		{
			name: "unverified",
			identity: models.IdentityContext{
				ID: "desktop-agent", Verified: false, Source: "mcp_initialize",
			},
			action: models.Action{
				AgentID: "desktop-agent", Tool: "filesystem.read", Operation: "read",
				Arguments: map[string]any{"path": "./README.md"},
			},
			source: "identity_unverified",
		},
		{
			name: "unknown",
			identity: models.IdentityContext{
				ID: "unknown-agent", Verified: true, Source: "operator_config",
			},
			action: models.Action{AgentID: "unknown-agent", Tool: "filesystem.read", Operation: "read"},
			source: "identity_unknown",
		},
		{
			name: "outside capability",
			identity: models.IdentityContext{
				ID: "desktop-agent", Verified: true, Source: "operator_config",
			},
			action: models.Action{
				AgentID: "desktop-agent", Tool: "shell.exec", Operation: "execute",
				Arguments: map[string]any{"command": "npm test"},
			},
			source: "capability_denied",
		},
		{
			name: "trusted context mismatch",
			identity: models.IdentityContext{
				ID: "desktop-agent", Verified: true, Source: "operator_config",
			},
			action: models.Action{AgentID: "other-agent", Tool: "filesystem.read", Operation: "read"},
			source: "identity_mismatch",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := AuthorizeIdentity(config, test.identity, test.action)
			if result.Allowed || result.DecisionSource != test.source {
				t.Fatalf("identity result = %#v, want %s denial", result, test.source)
			}
		})
	}
}

func TestIdentityValidationRejectsAmbiguousPrincipalsAndEmptyCapabilities(t *testing.T) {
	tests := []IdentityConfig{
		{
			EnforceCapabilities: true,
		},
		{
			EnforceCapabilities: true,
			Agents: []AgentIdentity{{
				ID: "one",
				Capabilities: []Capability{{
					ID:    "read",
					Match: Match{Tool: StringList{"filesystem.read"}},
				}},
			}},
		},
		{
			Agents: []AgentIdentity{
				{ID: "one", Aliases: StringList{"shared"}},
				{ID: "two", Aliases: StringList{"Shared"}},
			},
		},
		{
			Agents: []AgentIdentity{{
				ID: "one", Capabilities: []Capability{{ID: "everything"}},
			}},
		},
	}
	for _, identity := range tests {
		config := DefaultConfig()
		config.Identity = identity
		if err := config.Validate(); err == nil {
			t.Fatalf("identity config unexpectedly valid: %#v", identity)
		}
	}
}

func TestIdentitySecurityChangesPolicyDigest(t *testing.T) {
	base := DefaultConfig()
	first, err := Digest(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Identity.RequireVerified = true
	second, err := Digest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(first, second) {
		t.Fatal("identity security change did not alter policy digest")
	}
}

func identityTestConfig() Config {
	config := DefaultConfig()
	config.Identity = IdentityConfig{
		RequireVerified: true, EnforceCapabilities: true,
		Agents: []AgentIdentity{{
			ID: "desktop-agent", Aliases: StringList{"Claude Desktop"},
			Capabilities: []Capability{{
				ID: "workspace-read",
				Match: Match{
					Tool:   StringList{"filesystem.read"},
					Action: StringList{"read"},
					Path:   StringList{"./**"},
				},
			}},
		}},
	}
	return config
}

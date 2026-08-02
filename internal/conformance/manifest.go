// Package conformance implements Latch's versioned cross-adapter security
// contract and offline certification runner.
package conformance

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const SchemaVersion = "latch.conformance/v1"

//go:embed testdata/v1/manifest.json
var manifestPayload []byte

type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	SuiteVersion  string         `json:"suite_version"`
	DecisionCases []DecisionCase `json:"decision_cases"`
	WireCases     []WireCase     `json:"wire_cases"`
	ClientCases   []ClientCase   `json:"client_cases"`
}

type DecisionCase struct {
	ID          string       `json:"id"`
	Description string       `json:"description"`
	Setup       string       `json:"setup,omitempty"`
	Action      api.Action   `json:"action"`
	Expected    ExpectedCase `json:"expected"`
}

type ExpectedCase struct {
	Decision       models.Decision `json:"decision"`
	DecisionSource string          `json:"decision_source"`
	Forwarded      bool            `json:"forwarded"`
	HardDeny       bool            `json:"hard_deny,omitempty"`
	FailClosed     bool            `json:"fail_closed,omitempty"`
	TriggeredRules []string        `json:"triggered_rules,omitempty"`
}

type WireCase struct {
	ID             string `json:"id"`
	Description    string `json:"description"`
	Setup          string `json:"setup,omitempty"`
	Payload        string `json:"payload,omitempty"`
	ExpectedStatus int    `json:"expected_status"`
	ExpectedError  string `json:"expected_error"`
}

type ClientCase struct {
	ID       string `json:"id"`
	Response string `json:"response"`
	Execute  bool   `json:"execute"`
}

func LoadManifest() (Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode embedded conformance manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ManifestJSON() []byte {
	return append([]byte(nil), manifestPayload...)
}

func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("conformance schema must be %q", SchemaVersion)
	}
	if strings.TrimSpace(manifest.SuiteVersion) == "" {
		return fmt.Errorf("conformance suite_version is required")
	}
	if len(manifest.DecisionCases) == 0 || len(manifest.WireCases) == 0 || len(manifest.ClientCases) == 0 {
		return fmt.Errorf("conformance decision, wire, and client profiles must not be empty")
	}
	seen := map[string]struct{}{}
	for _, test := range manifest.DecisionCases {
		if err := uniqueRequirement(seen, test.ID, test.Description); err != nil {
			return err
		}
		if strings.TrimSpace(test.Action.Tool) == "" {
			return fmt.Errorf("conformance requirement %q has no action tool", test.ID)
		}
		switch test.Expected.Decision {
		case models.DecisionAllow, models.DecisionBlock, models.DecisionRequireApproval:
		default:
			return fmt.Errorf("conformance requirement %q has invalid decision %q", test.ID, test.Expected.Decision)
		}
		if strings.TrimSpace(test.Expected.DecisionSource) == "" {
			return fmt.Errorf("conformance requirement %q has no decision source", test.ID)
		}
	}
	for _, test := range manifest.WireCases {
		if err := uniqueRequirement(seen, test.ID, test.Description); err != nil {
			return err
		}
		if test.ExpectedStatus < 400 || strings.TrimSpace(test.ExpectedError) == "" {
			return fmt.Errorf("wire requirement %q has no rejection contract", test.ID)
		}
	}
	for _, test := range manifest.ClientCases {
		if err := uniqueRequirement(seen, test.ID, test.Response); err != nil {
			return err
		}
		switch test.Response {
		case "allow", "block", "require_approval", "unknown_decision", "version_mismatch", "request_id_mismatch", "malformed", "oversized", "redirect", "unavailable":
		default:
			return fmt.Errorf("client requirement %q has unsupported response %q", test.ID, test.Response)
		}
		if test.Response != "allow" && test.Execute {
			return fmt.Errorf("client requirement %q executes without an explicit ALLOW", test.ID)
		}
	}
	return nil
}

func uniqueRequirement(seen map[string]struct{}, id, description string) error {
	id = strings.TrimSpace(id)
	if id == "" || strings.TrimSpace(description) == "" {
		return fmt.Errorf("conformance requirement id and description are required")
	}
	if _, duplicate := seen[id]; duplicate {
		return fmt.Errorf("duplicate conformance requirement %q", id)
	}
	seen[id] = struct{}{}
	return nil
}

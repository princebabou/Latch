package api_test

import (
	"os"
	"strings"
	"testing"

	api "github.com/princebabou/Latch/pkg/api/v1"
	"gopkg.in/yaml.v3"
)

func TestOpenAPIContractParsesAndMatchesV1Constants(t *testing.T) {
	data, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		OpenAPI string `yaml:"openapi"`
		Info    struct {
			Version string `yaml:"version"`
		} `yaml:"info"`
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse OpenAPI contract: %v", err)
	}
	if document.OpenAPI != "3.1.0" || document.Info.Version != "1.0.0" {
		t.Fatalf("contract versions = OpenAPI %q, API %q", document.OpenAPI, document.Info.Version)
	}
	if _, ok := document.Paths["/v1/decisions"]; !ok {
		t.Fatal("contract does not define /v1/decisions")
	}
	contract := string(data)
	if !strings.Contains(contract, "const: "+api.APIVersion) || !strings.Contains(contract, api.MediaType+":") {
		t.Fatal("contract constants do not match the Go v1 package")
	}
}

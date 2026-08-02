package conformance

import (
	"context"
	"encoding/json"
	"testing"
)

func TestManifestIsVersionedUniqueAndPortable(t *testing.T) {
	manifest, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != SchemaVersion || len(manifest.DecisionCases) < 7 || len(manifest.WireCases) < 6 || len(manifest.ClientCases) < 10 {
		t.Fatalf("manifest = %#v", manifest)
	}
	if !json.Valid(ManifestJSON()) {
		t.Fatal("embedded manifest is not valid JSON")
	}
}

func TestBuiltInAdaptersPassConformance(t *testing.T) {
	report := Run(context.Background())
	if !report.Passed {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		t.Fatalf("conformance failed:\n%s", encoded)
	}
	if report.FailedCount != 0 || report.PassedCount != report.Total || len(report.Adapters) < 6 {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := Run(ctx)
	if report.Passed || report.FailedCount == 0 {
		t.Fatalf("cancelled report = %#v", report)
	}
}

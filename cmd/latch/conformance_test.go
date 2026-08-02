package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/princebabou/Latch/internal/conformance"
)

func TestConformanceCommandReportsPassingAdapters(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"conformance"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q, stdout = %q", code, errOut.String(), out.String())
	}
	for _, wanted := range []string{"LATCH CONFORMANCE", "decision-core", "enforcement-api-wire", "Result: 41/41 passed"} {
		if !strings.Contains(out.String(), wanted) {
			t.Fatalf("stdout %q does not contain %q", out.String(), wanted)
		}
	}
}

func TestConformanceCommandJSONAndManifestAreMachineReadable(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"conformance", "--json"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
	var report conformance.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || !report.Passed {
		t.Fatalf("report = %#v, error = %v", report, err)
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"conformance", "--manifest"}, strings.NewReader(""), &out, &errOut)
	if code != 0 || !json.Valid(out.Bytes()) || !strings.Contains(out.String(), conformance.SchemaVersion) {
		t.Fatalf("exit code = %d, stderr = %q, manifest = %q", code, errOut.String(), out.String())
	}
}

func TestConformanceCommandRejectsUnsafeTimeout(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"conformance", "--timeout", "0"}, strings.NewReader(""), &out, &errOut)
	if code != 64 || !strings.Contains(errOut.String(), "--timeout") {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
}

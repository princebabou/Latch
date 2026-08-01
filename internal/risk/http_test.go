package risk

import (
	"net/http"
	"testing"

	"github.com/princebabou/Latch/pkg/models"
)

func TestHTTPAnalyzerClassifiesDestinationsAndDataFlow(t *testing.T) {
	tests := []struct {
		name      string
		arguments map[string]any
		want      []string
		doNotWant []string
	}{
		{
			name:      "public destination",
			arguments: map[string]any{"url": "https://api.example.test/v1"},
			want:      []string{"outbound-network"},
		},
		{
			name:      "loopback is not outbound",
			arguments: map[string]any{"url": "https://localhost:8443/v1"},
			doNotWant: []string{"outbound-network", "internal-network-access"},
		},
		{
			name:      "numeric loopback is recognized",
			arguments: map[string]any{"url": "http://2130706433/admin"},
			doNotWant: []string{"outbound-network", "internal-network-access"},
		},
		{
			name:      "private destination",
			arguments: map[string]any{"url": "https://10.1.2.3/admin"},
			want:      []string{"internal-network-access"},
		},
		{
			name:      "cloud metadata endpoint",
			arguments: map[string]any{"url": "http://169.254.169.254/latest/meta-data"},
			want:      []string{"cloud-metadata-access"},
		},
		{
			name:      "percent-encoded secret query key",
			arguments: map[string]any{"url": "https://api.example.test/export?api%5Fkey=value"},
			want:      []string{"secret-in-url"},
		},
		{
			name: "typed authorization header",
			arguments: map[string]any{
				"url":     "https://api.example.test/v1",
				"headers": http.Header{"Authorization": {"Bearer value"}},
			},
			want: []string{"credential-exfiltration"},
		},
		{
			name: "nested JSON secret payload",
			arguments: map[string]any{
				"url":  "https://api.example.test/v1",
				"body": `{"profile":{"refresh_token":"value"}}`,
			},
			want: []string{"sensitive-data-exfiltration"},
		},
		{
			name: "malformed JSON secret payload",
			arguments: map[string]any{
				"url":  "https://api.example.test/v1",
				"body": `{"refresh_token":"value"`,
			},
			want: []string{"sensitive-data-exfiltration"},
		},
		{
			name: "secret over cleartext transport",
			arguments: map[string]any{
				"url":     "http://api.example.test/v1",
				"headers": map[string]any{"Authorization": "Bearer value"},
			},
			want: []string{"credential-exfiltration", "cleartext-secret-transport"},
		},
		{
			name:      "destructive method",
			arguments: map[string]any{"url": "https://api.example.test/v1/item", "method": "DELETE"},
			want:      []string{"destructive-http-request"},
		},
		{
			name: "opaque body requires scrutiny",
			arguments: map[string]any{
				"url": "https://api.example.test/upload", "method": "POST", "body_inspected": false,
			},
			want: []string{"uninspected-http-body"},
		},
		{
			name:      "malformed endpoint",
			arguments: map[string]any{"url": "api.example.test/v1"},
			want:      []string{"http-parse-ambiguity"},
		},
		{
			name:      "non-text endpoint",
			arguments: map[string]any{"url": map[string]any{"host": "example.test"}},
			want:      []string{"http-parse-ambiguity"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, signals := Analyze(models.Action{
				AgentID: "test", Tool: "http.request", Operation: "network", Arguments: test.arguments,
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

func TestHTTPSecretValuesDoNotTriggerWithoutSensitiveStructure(t *testing.T) {
	_, signals := Analyze(models.Action{
		AgentID: "test", Tool: "http.request", Operation: "network",
		Arguments: map[string]any{
			"url":  "https://api.example.test/v1",
			"body": map[string]any{"note": "the word password is documentation"},
		},
	})
	names := riskSignalNames(signals)
	if names["sensitive-data-exfiltration"] {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestCloudMetadataAndCredentialExfiltrationAreHardDenies(t *testing.T) {
	for _, arguments := range []map[string]any{
		{"url": "http://100.100.100.200/latest/meta-data"},
		{"url": "https://api.example.test", "headers": map[string]string{"X-API-Key": "value"}},
	} {
		_, signals := Analyze(models.Action{AgentID: "test", Tool: "http.request", Operation: "network", Arguments: arguments})
		if len(HardDeny(signals)) == 0 {
			t.Fatalf("signals = %#v, want hard deny", signals)
		}
	}
}

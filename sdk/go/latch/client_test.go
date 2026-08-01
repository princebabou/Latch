package latch

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

func TestClientDecideSendsV1ContractAndAuthenticates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/decisions" || request.Header.Get("Authorization") != "Bearer test-token" || request.Header.Get("Content-Type") != api.MediaType {
			t.Errorf("request = %s, headers = %#v", request.URL.Path, request.Header)
		}
		var input api.DecisionRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", api.MediaType)
		_ = json.NewEncoder(response).Encode(api.DecisionResponse{
			APIVersion: api.APIVersion, RequestID: input.RequestID, Decision: models.DecisionAllow,
			Risk: api.Risk{Score: 0, Level: "LOW"}, Identity: api.Identity{Verified: true},
			Policy: api.PolicyResult{DecisionSource: "default_allow"},
		})
	}))
	defer server.Close()
	client, err := New(server.URL, WithToken("test-token"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Decide(context.Background(), api.Action{Tool: "filesystem.read"})
	if err != nil || result.Decision != models.DecisionAllow {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
}

func TestGuardExecutesOnlyExplicitAllow(t *testing.T) {
	for _, decision := range []models.Decision{models.DecisionAllow, models.DecisionBlock, models.DecisionRequireApproval} {
		t.Run(string(decision), func(t *testing.T) {
			server := decisionServer(t, decision)
			defer server.Close()
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			var executed atomic.Bool
			_, err = client.Guard(context.Background(), api.Action{Tool: "shell.exec"}, func(context.Context) error {
				executed.Store(true)
				return nil
			})
			if decision == models.DecisionAllow {
				if err != nil || !executed.Load() {
					t.Fatalf("allow error = %v, executed = %t", err, executed.Load())
				}
				return
			}
			if !IsNotAllowed(err) || executed.Load() {
				t.Fatalf("decision = %s, error = %v, executed = %t", decision, err, executed.Load())
			}
		})
	}
}

func TestClientFailsClosedOnUnavailableInvalidAndRedirectedResponses(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		client, err := New("http://127.0.0.1:1", WithTimeout(100*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Decide(context.Background(), api.Action{Tool: "filesystem.read"})
		var unavailable *UnavailableError
		if !errors.As(err, &unavailable) {
			t.Fatalf("error = %T %v", err, err)
		}
	})

	for name, handler := range map[string]http.HandlerFunc{
		"invalid JSON": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", api.MediaType)
			_, _ = response.Write([]byte("not-json"))
		},
		"redirect": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Location", "https://example.invalid")
			response.WriteHeader(http.StatusTemporaryRedirect)
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Decide(context.Background(), api.Action{Tool: "filesystem.read"})
			if err == nil {
				t.Fatal("unsafe response did not fail closed")
			}
		})
	}
}

func TestClientRejectsMismatchedRequestAndOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", api.MediaType)
		_ = json.NewEncoder(response).Encode(api.DecisionResponse{
			APIVersion: api.APIVersion, RequestID: "req_wrong000", Decision: models.DecisionAllow,
			Risk: api.Risk{Level: "LOW"}, Identity: api.Identity{}, Policy: api.PolicyResult{DecisionSource: "default_allow"},
		})
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Decide(context.Background(), api.Action{Tool: "filesystem.read"}); err == nil {
		t.Fatal("mismatched request id was accepted")
	}

	large := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", api.MediaType)
		_, _ = response.Write(make([]byte, 2048))
	}))
	defer large.Close()
	client, err = New(large.URL, WithMaxResponseBytes(1024))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Decide(context.Background(), api.Action{Tool: "filesystem.read"}); err == nil {
		t.Fatal("oversized response was accepted")
	}
}

func decisionServer(t *testing.T, decision models.Decision) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var input api.DecisionRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", api.MediaType)
		_ = json.NewEncoder(response).Encode(api.DecisionResponse{
			APIVersion: api.APIVersion, RequestID: input.RequestID, Decision: decision,
			Risk: api.Risk{Score: 1, Level: "LOW"}, Identity: api.Identity{},
			Policy: api.PolicyResult{DecisionSource: "test"},
		})
	}))
}

func TestClientAgainstLiveAPI(t *testing.T) {
	serverURL := os.Getenv("LATCH_TEST_URL")
	if serverURL == "" {
		t.Skip("LATCH_TEST_URL is not set")
	}
	options := []Option{}
	if token := os.Getenv("LATCH_API_TOKEN"); token != "" {
		options = append(options, WithToken(token))
	}
	client, err := New(serverURL, options...)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Decide(context.Background(), api.Action{Tool: "filesystem.read", Arguments: map[string]any{"path": "./README.md"}})
	if err != nil || result.Decision != models.DecisionAllow || !result.Identity.Verified {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
}

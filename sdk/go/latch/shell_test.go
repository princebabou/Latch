package latch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

type fakeShellClient struct {
	actions  []api.Action
	decision models.Decision
	err      error
	after    func()
}

func (client *fakeShellClient) Decide(_ context.Context, action api.Action) (api.DecisionResponse, error) {
	client.actions = append(client.actions, action)
	if client.after != nil {
		client.after()
	}
	if client.err != nil {
		return api.DecisionResponse{}, client.err
	}
	decision := client.decision
	if decision == "" {
		decision = models.DecisionAllow
	}
	return api.DecisionResponse{Decision: decision}, nil
}

func TestShellHelperProcess(t *testing.T) {
	if os.Getenv("LATCH_SHELL_HELPER") != "1" {
		return
	}
	if marker := os.Getenv("LATCH_SHELL_MARKER"); marker != "" {
		_ = os.WriteFile(marker, []byte("started"), 0o600)
	}
	mode := os.Getenv("LATCH_SHELL_MODE")
	switch mode {
	case "sleep":
		time.Sleep(2 * time.Second)
	case "output":
		fmt.Print(strings.Repeat("x", 4096))
	default:
		input, _ := io.ReadAll(os.Stdin)
		separator := len(os.Args)
		for index, argument := range os.Args {
			if argument == "--" {
				separator = index + 1
				break
			}
		}
		fmt.Printf("%s|%s|%s", strings.Join(os.Args[separator:], ","), os.Getenv("LATCH_SHELL_VALUE"), input)
	}
	os.Exit(0)
}

func TestShellStructuredCommandAllowedAndNormalized(t *testing.T) {
	client := &fakeShellClient{}
	executor, err := NewShellExecutor(client)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Run(context.Background(), ShellCommand{
		ExecutionID: "exec_allowed_001", Executable: os.Args[0],
		Args: []string{"-test.run=TestShellHelperProcess", "--", "one", "two"},
		Environment: map[string]string{
			"LATCH_SHELL_HELPER": "1", "LATCH_SHELL_VALUE": "secret-value",
		},
		Stdin: "payload",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || string(result.Stdout) != "one,two|secret-value|payload" {
		t.Fatalf("result = %#v", result)
	}
	if len(client.actions) != 1 {
		t.Fatalf("actions = %d", len(client.actions))
	}
	action := client.actions[0]
	if action.Tool != "shell.exec" || action.Operation != "execute" || action.Metadata["surface"] != "argv" {
		t.Fatalf("action = %#v", action)
	}
	if action.Resource == "" || !filepath.IsAbs(action.Resource) {
		t.Fatalf("resource = %q", action.Resource)
	}
	encoded, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-value") || strings.Contains(string(encoded), "payload") {
		t.Fatalf("sensitive process data leaked into action: %s", encoded)
	}
	if action.Arguments["environment_sha256"] == "" || action.Arguments["stdin_sha256"] == "" {
		t.Fatalf("missing snapshot digests: %#v", action.Arguments)
	}
}

func TestShellDenialAndUnavailableStartNothing(t *testing.T) {
	for _, test := range []struct {
		name           string
		client         *fakeShellClient
		wantNotAllowed bool
	}{
		{"block", &fakeShellClient{decision: models.DecisionBlock}, true},
		{"approval", &fakeShellClient{decision: models.DecisionRequireApproval}, true},
		{"unavailable", &fakeShellClient{err: errors.New("offline")}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "started")
			executor, _ := NewShellExecutor(test.client)
			_, err := executor.Run(context.Background(), ShellCommand{
				ExecutionID: "exec_denied_001", Executable: os.Args[0],
				Args:        []string{"-test.run=TestShellHelperProcess"},
				Environment: map[string]string{"LATCH_SHELL_HELPER": "1", "LATCH_SHELL_MARKER": marker},
			})
			if err == nil {
				t.Fatal("expected error")
			}
			var notAllowed *ShellNotAllowedError
			if test.wantNotAllowed && !errors.As(err, &notAllowed) {
				t.Fatalf("error = %T %v, want ShellNotAllowedError", err, err)
			}
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Fatalf("process started: %v", statErr)
			}
		})
	}
}

func TestShellReplayAndFailureStayConsumed(t *testing.T) {
	client := &fakeShellClient{}
	executor, _ := NewShellExecutor(client, WithShellTimeout(50*time.Millisecond))
	command := ShellCommand{
		ExecutionID: "exec_replay_001", Executable: os.Args[0],
		Args:        []string{"-test.run=TestShellHelperProcess"},
		Environment: map[string]string{"LATCH_SHELL_HELPER": "1", "LATCH_SHELL_MODE": "sleep"},
	}
	_, firstErr := executor.Run(context.Background(), command)
	var executionError *ShellExecutionError
	if !errors.As(firstErr, &executionError) {
		t.Fatalf("first error = %T %v", firstErr, firstErr)
	}
	_, secondErr := executor.Run(context.Background(), command)
	var replayError *ShellReplayError
	if !errors.As(secondErr, &replayError) || len(client.actions) != 1 {
		t.Fatalf("second error/actions = %v / %d", secondErr, len(client.actions))
	}
}

func TestShellRejectsExecutableChangeAfterApproval(t *testing.T) {
	copyPath := filepath.Join(t.TempDir(), "helper")
	if runtime.GOOS == "windows" {
		copyPath += ".exe"
	}
	payload, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "started")
	client := &fakeShellClient{after: func() {
		file, openErr := os.OpenFile(copyPath, os.O_APPEND|os.O_WRONLY, 0)
		if openErr == nil {
			_, _ = file.Write([]byte("changed"))
			_ = file.Close()
		}
	}}
	executor, _ := NewShellExecutor(client)
	_, err = executor.Run(context.Background(), ShellCommand{
		ExecutionID: "exec_changed_01", Executable: copyPath,
		Args:        []string{"-test.run=TestShellHelperProcess"},
		Environment: map[string]string{"LATCH_SHELL_HELPER": "1", "LATCH_SHELL_MARKER": marker},
	})
	var protocolError *ShellProtocolError
	if !errors.As(err, &protocolError) {
		t.Fatalf("error = %T %v", err, err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("changed executable started: %v", statErr)
	}
}

func TestShellOutputLimitAndEnvironmentConflicts(t *testing.T) {
	client := &fakeShellClient{}
	executor, _ := NewShellExecutor(client, WithShellMaxOutputBytes(1024))
	_, err := executor.Run(context.Background(), ShellCommand{
		ExecutionID: "exec_output_001", Executable: os.Args[0],
		Args:        []string{"-test.run=TestShellHelperProcess"},
		Environment: map[string]string{"LATCH_SHELL_HELPER": "1", "LATCH_SHELL_MODE": "output"},
	})
	var executionError *ShellExecutionError
	if !errors.As(err, &executionError) || len(executionError.Result.Stdout) != 1024 {
		t.Fatalf("error/result = %v / %#v", err, executionError)
	}

	conflictClient := &fakeShellClient{}
	conflictExecutor, _ := NewShellExecutor(conflictClient)
	_, err = conflictExecutor.Run(context.Background(), ShellCommand{
		ExecutionID: "exec_env_conflict", Executable: os.Args[0],
		Environment: map[string]string{"LATCH_VALUE": "one"}, UnsetEnvironment: []string{"LATCH_VALUE"},
	})
	var protocolError *ShellProtocolError
	if !errors.As(err, &protocolError) || len(conflictClient.actions) != 0 {
		t.Fatalf("error/actions = %v / %d", err, len(conflictClient.actions))
	}
}

func TestShellExplicitScript(t *testing.T) {
	client := &fakeShellClient{}
	executor, _ := NewShellExecutor(client)
	result, err := executor.RunShell(context.Background(), ShellScript{
		ExecutionID: "exec_script_001", Command: "echo shell-ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || !strings.Contains(string(result.Stdout), "shell-ok") {
		t.Fatalf("result = %#v", result)
	}
	if client.actions[0].Arguments["command"] != "echo shell-ok" || client.actions[0].Metadata["surface"] != "shell" {
		t.Fatalf("action = %#v", client.actions[0])
	}
}

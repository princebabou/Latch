package latch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	api "github.com/princebabou/Latch/pkg/api/v1"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	defaultShellTimeout        = 30 * time.Second
	defaultShellMaxInputBytes  = 1 << 20
	defaultShellMaxOutputBytes = 4 << 20
	defaultShellReplayCapacity = 10_000
)

var shellExecutionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)

// ShellDecisionClient is implemented by Client and keeps process execution easy to test.
type ShellDecisionClient interface {
	Decide(context.Context, api.Action) (api.DecisionResponse, error)
}

// ShellCommand describes one structured local process. ExecutionID must be
// stable across delivery retries so the executor can reject accidental replay.
type ShellCommand struct {
	ExecutionID      string
	Executable       string
	Args             []string
	WorkingDirectory string
	Environment      map[string]string
	UnsetEnvironment []string
	ClearEnvironment bool
	Stdin            string
}

// ShellScript describes an explicit system-shell invocation. Prefer
// ShellCommand whenever a program can be expressed as executable plus argv.
type ShellScript struct {
	ExecutionID      string
	Command          string
	WorkingDirectory string
	Environment      map[string]string
	UnsetEnvironment []string
	ClearEnvironment bool
	Stdin            string
}

type ShellResult struct {
	Decision api.DecisionResponse
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

type ShellExecutorOption func(*ShellExecutor) error

func WithShellTimeout(timeout time.Duration) ShellExecutorOption {
	return func(executor *ShellExecutor) error {
		if timeout <= 0 || timeout > 24*time.Hour {
			return fmt.Errorf("shell timeout must be between 1ns and 24h")
		}
		executor.timeout = timeout
		return nil
	}
}

func WithShellMaxInputBytes(limit int) ShellExecutorOption {
	return func(executor *ShellExecutor) error {
		if limit < 0 || limit > 16<<20 {
			return fmt.Errorf("shell input limit must be between 0 and 16777216 bytes")
		}
		executor.maxInputBytes = limit
		return nil
	}
}

func WithShellMaxOutputBytes(limit int) ShellExecutorOption {
	return func(executor *ShellExecutor) error {
		if limit < 1024 || limit > 64<<20 {
			return fmt.Errorf("shell output limit must be between 1024 and 67108864 bytes")
		}
		executor.maxOutputBytes = limit
		return nil
	}
}

func WithShellReplayCapacity(capacity int) ShellExecutorOption {
	return func(executor *ShellExecutor) error {
		if capacity < 128 || capacity > 1_000_000 {
			return fmt.Errorf("shell replay capacity must be between 128 and 1000000")
		}
		executor.replayCapacity = capacity
		return nil
	}
}

// ShellExecutor starts a local process only after an explicit Latch ALLOW.
// Prepared values are immutable snapshots: the approved executable, cwd,
// environment, argv, and stdin are the exact values passed to the child.
type ShellExecutor struct {
	client         ShellDecisionClient
	timeout        time.Duration
	maxInputBytes  int
	maxOutputBytes int
	replayCapacity int
	replayMu       sync.Mutex
	replayed       map[string]struct{}
	replayOrder    []string
}

func NewShellExecutor(client ShellDecisionClient, options ...ShellExecutorOption) (*ShellExecutor, error) {
	if client == nil {
		return nil, fmt.Errorf("Latch decision client cannot be nil")
	}
	executor := &ShellExecutor{
		client: client, timeout: defaultShellTimeout,
		maxInputBytes: defaultShellMaxInputBytes, maxOutputBytes: defaultShellMaxOutputBytes,
		replayCapacity: defaultShellReplayCapacity, replayed: make(map[string]struct{}),
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("shell executor option cannot be nil")
		}
		if err := option(executor); err != nil {
			return nil, err
		}
	}
	return executor, nil
}

// Run executes a structured argv command without invoking a command shell.
func (executor *ShellExecutor) Run(ctx context.Context, command ShellCommand) (ShellResult, error) {
	prepared, err := executor.prepare(
		command.ExecutionID, "argv", command.Executable, command.Args, "",
		command.WorkingDirectory, command.Environment, command.UnsetEnvironment,
		command.ClearEnvironment, command.Stdin,
	)
	if err != nil {
		return ShellResult{}, err
	}
	return executor.execute(ctx, prepared)
}

// RunShell executes a command through the platform system shell. It is
// deliberately separate so callers cannot enable shell parsing accidentally.
func (executor *ShellExecutor) RunShell(ctx context.Context, script ShellScript) (ShellResult, error) {
	if strings.TrimSpace(script.Command) == "" {
		return ShellResult{}, &ShellProtocolError{Message: "shell command cannot be empty"}
	}
	if err := validateShellText(script.Command, "shell command", 1<<20); err != nil {
		return ShellResult{}, err
	}
	shell, args, err := platformShell(script.Command)
	if err != nil {
		return ShellResult{}, err
	}
	prepared, err := executor.prepare(
		script.ExecutionID, "shell", shell, args, script.Command,
		script.WorkingDirectory, script.Environment, script.UnsetEnvironment,
		script.ClearEnvironment, script.Stdin,
	)
	if err != nil {
		return ShellResult{}, err
	}
	return executor.execute(ctx, prepared)
}

type preparedShellCommand struct {
	executionID    string
	mode           string
	executable     string
	executableHash string
	args           []string
	directory      string
	environment    []string
	stdin          string
	action         api.Action
}

func (executor *ShellExecutor) prepare(
	executionID, mode, executable string, args []string, shellCommand, directory string,
	environment map[string]string, unset []string, clearEnvironment bool, stdin string,
) (preparedShellCommand, error) {
	if !shellExecutionIDPattern.MatchString(executionID) {
		return preparedShellCommand{}, &ShellProtocolError{Message: "execution ID must be 8-128 safe ASCII characters"}
	}
	if executor.wasReplayed(executionID) {
		return preparedShellCommand{}, &ShellReplayError{ExecutionID: executionID}
	}
	if len(stdin) > executor.maxInputBytes {
		return preparedShellCommand{}, &ShellProtocolError{Message: fmt.Sprintf("stdin exceeds %d bytes", executor.maxInputBytes)}
	}
	if !utf8.ValidString(stdin) || strings.ContainsRune(stdin, utf8.RuneError) || strings.IndexByte(stdin, 0) >= 0 {
		return preparedShellCommand{}, &ShellProtocolError{Message: "stdin must contain valid interoperable UTF-8 without NUL bytes"}
	}
	resolvedExecutable, executableHash, err := resolveShellExecutable(executable)
	if err != nil {
		return preparedShellCommand{}, err
	}
	resolvedDirectory, err := resolveShellDirectory(directory)
	if err != nil {
		return preparedShellCommand{}, err
	}
	validatedArgs, err := validateShellArgs(args)
	if err != nil {
		return preparedShellCommand{}, err
	}
	environmentSnapshot, environmentDigest, changes, err := prepareShellEnvironment(environment, unset, clearEnvironment)
	if err != nil {
		return preparedShellCommand{}, err
	}
	stdinSum := sha256.Sum256([]byte(stdin))
	arguments := map[string]any{
		"execution_id":        executionID,
		"mode":                mode,
		"executable":          resolvedExecutable,
		"executable_sha256":   executableHash,
		"args":                append([]string(nil), validatedArgs...),
		"cwd":                 resolvedDirectory,
		"clear_environment":   clearEnvironment,
		"environment_sha256":  environmentDigest,
		"environment_changes": changes,
		"stdin_sha256":        hex.EncodeToString(stdinSum[:]),
		"stdin_bytes":         len(stdin),
		"timeout_ms":          executor.timeout.Milliseconds(),
	}
	if mode == "shell" {
		arguments["command"] = shellCommand
	} else {
		words := make([]string, 0, len(validatedArgs)+1)
		words = append(words, resolvedExecutable)
		words = append(words, validatedArgs...)
		arguments["command"] = words
	}
	return preparedShellCommand{
		executionID: executionID, mode: mode, executable: resolvedExecutable,
		executableHash: executableHash, args: validatedArgs, directory: resolvedDirectory,
		environment: environmentSnapshot, stdin: stdin,
		action: api.Action{
			Tool: "shell.exec", Operation: "execute", Resource: resolvedExecutable,
			Arguments: arguments,
			Metadata:  map[string]any{"protocol": "local-process", "surface": mode, "platform": runtime.GOOS},
		},
	}, nil
}

func (executor *ShellExecutor) execute(ctx context.Context, prepared preparedShellCommand) (ShellResult, error) {
	decision, err := executor.client.Decide(ctx, prepared.action)
	if err != nil {
		return ShellResult{}, err
	}
	if decision.Decision != models.DecisionAllow || decision.FailClosed {
		return ShellResult{Decision: decision, ExitCode: -1}, &ShellNotAllowedError{
			ExecutionID: prepared.executionID, Response: decision,
		}
	}
	if err := verifyShellExecutable(prepared.executable, prepared.executableHash); err != nil {
		return ShellResult{Decision: decision, ExitCode: -1}, err
	}
	resolvedDirectory, err := resolveShellDirectory(prepared.directory)
	if err != nil || resolvedDirectory != prepared.directory {
		if err == nil {
			err = &ShellProtocolError{Message: "working directory changed after approval"}
		}
		return ShellResult{Decision: decision, ExitCode: -1}, err
	}
	if err := executor.reserve(prepared.executionID); err != nil {
		return ShellResult{Decision: decision, ExitCode: -1}, err
	}
	if err := ctx.Err(); err != nil {
		return ShellResult{Decision: decision, ExitCode: -1}, &ShellExecutionError{ExecutionID: prepared.executionID, Cause: err}
	}
	processContext, cancel := context.WithTimeout(ctx, executor.timeout)
	defer cancel()
	command := exec.CommandContext(processContext, prepared.executable, prepared.args...)
	command.Dir = prepared.directory
	command.Env = append([]string(nil), prepared.environment...)
	command.Stdin = strings.NewReader(prepared.stdin)
	stdout := &boundedShellBuffer{limit: executor.maxOutputBytes}
	stderr := &boundedShellBuffer{limit: executor.maxOutputBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	result := ShellResult{Decision: decision, ExitCode: shellExitCode(runErr), Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if stdout.overflow || stderr.overflow {
		return result, &ShellExecutionError{ExecutionID: prepared.executionID, Result: result, Cause: fmt.Errorf("process output exceeds %d bytes per stream", executor.maxOutputBytes)}
	}
	if processContext.Err() != nil {
		return result, &ShellExecutionError{ExecutionID: prepared.executionID, Result: result, Cause: processContext.Err()}
	}
	if runErr != nil {
		return result, &ShellExecutionError{ExecutionID: prepared.executionID, Result: result, Cause: runErr}
	}
	return result, nil
}

type ShellProtocolError struct{ Message string }

func (err *ShellProtocolError) Error() string {
	return "invalid shell action; process not executed: " + err.Message
}

type ShellReplayError struct{ ExecutionID string }

func (err *ShellReplayError) Error() string {
	return fmt.Sprintf("shell execution %q was duplicated or replayed; process not executed", err.ExecutionID)
}

type ShellNotAllowedError struct {
	ExecutionID string
	Response    api.DecisionResponse
}

func (err *ShellNotAllowedError) Error() string {
	return fmt.Sprintf("Latch decision for shell execution %q is %s; process not executed", err.ExecutionID, err.Response.Decision)
}

type ShellExecutionError struct {
	ExecutionID string
	Result      ShellResult
	Cause       error
}

func (err *ShellExecutionError) Error() string {
	return fmt.Sprintf("execute allowed shell action %q: %v", err.ExecutionID, err.Cause)
}

func (err *ShellExecutionError) Unwrap() error { return err.Cause }

func (executor *ShellExecutor) wasReplayed(executionID string) bool {
	executor.replayMu.Lock()
	defer executor.replayMu.Unlock()
	_, exists := executor.replayed[executionID]
	return exists
}

func (executor *ShellExecutor) reserve(executionID string) error {
	executor.replayMu.Lock()
	defer executor.replayMu.Unlock()
	if _, exists := executor.replayed[executionID]; exists {
		return &ShellReplayError{ExecutionID: executionID}
	}
	executor.replayed[executionID] = struct{}{}
	executor.replayOrder = append(executor.replayOrder, executionID)
	for len(executor.replayOrder) > executor.replayCapacity {
		oldest := executor.replayOrder[0]
		executor.replayOrder = executor.replayOrder[1:]
		delete(executor.replayed, oldest)
	}
	return nil
}

func resolveShellExecutable(value string) (string, string, error) {
	if err := validateShellText(value, "executable", 16<<10); err != nil {
		return "", "", err
	}
	path, err := exec.LookPath(value)
	if err != nil {
		return "", "", &ShellProtocolError{Message: "executable could not be resolved: " + err.Error()}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", &ShellProtocolError{Message: "executable path could not be made absolute"}
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", "", &ShellProtocolError{Message: "executable path could not be resolved: " + err.Error()}
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", "", &ShellProtocolError{Message: "executable must be a regular file"}
	}
	digest, err := shellFileDigest(resolved)
	if err != nil {
		return "", "", &ShellProtocolError{Message: "executable could not be fingerprinted: " + err.Error()}
	}
	return filepath.Clean(resolved), digest, nil
}

func verifyShellExecutable(path, expected string) error {
	digest, err := shellFileDigest(path)
	if err != nil || digest != expected {
		if err == nil {
			err = errors.New("content fingerprint changed")
		}
		return &ShellProtocolError{Message: "executable changed after approval: " + err.Error()}
	}
	return nil
}

func shellFileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func resolveShellDirectory(value string) (string, error) {
	if value == "" {
		var err error
		value, err = os.Getwd()
		if err != nil {
			return "", &ShellProtocolError{Message: "working directory could not be determined"}
		}
	}
	if err := validateShellText(value, "working directory", 16<<10); err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", &ShellProtocolError{Message: "working directory could not be made absolute"}
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", &ShellProtocolError{Message: "working directory could not be resolved: " + err.Error()}
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", &ShellProtocolError{Message: "working directory must be an existing directory"}
	}
	return filepath.Clean(resolved), nil
}

func validateShellArgs(args []string) ([]string, error) {
	if len(args) > 4096 {
		return nil, &ShellProtocolError{Message: "argv cannot exceed 4096 arguments"}
	}
	result := make([]string, len(args))
	total := 0
	for index, argument := range args {
		if len(argument) > 1<<20 {
			return nil, &ShellProtocolError{Message: fmt.Sprintf("argv[%d] exceeds 1048576 bytes", index)}
		}
		if !utf8.ValidString(argument) || strings.ContainsRune(argument, utf8.RuneError) || strings.IndexByte(argument, 0) >= 0 {
			return nil, &ShellProtocolError{Message: fmt.Sprintf("argv[%d] must contain valid interoperable UTF-8 without NUL bytes", index)}
		}
		total += len(argument)
		if total > 4<<20 {
			return nil, &ShellProtocolError{Message: "argv exceeds 4194304 bytes"}
		}
		result[index] = argument
	}
	return result, nil
}

func validateShellText(value, name string, limit int) error {
	if strings.TrimSpace(value) == "" {
		return &ShellProtocolError{Message: name + " cannot be empty"}
	}
	if len(value) > limit {
		return &ShellProtocolError{Message: fmt.Sprintf("%s exceeds %d bytes", name, limit)}
	}
	if !utf8.ValidString(value) || strings.ContainsRune(value, utf8.RuneError) || strings.IndexByte(value, 0) >= 0 {
		return &ShellProtocolError{Message: name + " must contain valid interoperable UTF-8 without NUL bytes"}
	}
	return nil
}

func prepareShellEnvironment(overrides map[string]string, unset []string, clear bool) ([]string, string, []map[string]any, error) {
	values := make(map[string]string)
	canonical := make(map[string]string)
	if !clear {
		for _, entry := range os.Environ() {
			name, value, found := strings.Cut(entry, "=")
			if !found {
				continue
			}
			key := shellEnvironmentKey(name)
			if old, exists := canonical[key]; exists {
				delete(values, old)
			}
			canonical[key] = name
			values[name] = value
		}
	}
	changes := make([]map[string]any, 0, len(overrides)+len(unset))
	changed := make(map[string]struct{}, len(overrides)+len(unset))
	for name, value := range overrides {
		if err := validateShellEnvironmentName(name); err != nil {
			return nil, "", nil, err
		}
		if !utf8.ValidString(value) || strings.ContainsRune(value, utf8.RuneError) || strings.IndexByte(value, 0) >= 0 {
			return nil, "", nil, &ShellProtocolError{Message: fmt.Sprintf("environment value for %q is invalid", name)}
		}
		key := shellEnvironmentKey(name)
		if _, exists := changed[key]; exists {
			return nil, "", nil, &ShellProtocolError{Message: fmt.Sprintf("environment variable %q is changed more than once", name)}
		}
		changed[key] = struct{}{}
		if old, exists := canonical[key]; exists {
			delete(values, old)
		}
		canonical[key] = name
		values[name] = value
		digest := sha256.Sum256([]byte(value))
		changes = append(changes, map[string]any{
			"name": name, "value_sha256": hex.EncodeToString(digest[:]), "value_bytes": len(value),
		})
	}
	for _, name := range unset {
		if err := validateShellEnvironmentName(name); err != nil {
			return nil, "", nil, err
		}
		key := shellEnvironmentKey(name)
		if _, exists := changed[key]; exists {
			return nil, "", nil, &ShellProtocolError{Message: fmt.Sprintf("environment variable %q is changed more than once", name)}
		}
		changed[key] = struct{}{}
		if old, exists := canonical[key]; exists {
			delete(values, old)
			delete(canonical, key)
		}
		changes = append(changes, map[string]any{"name": name, "unset": true})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i]["name"].(string) < changes[j]["name"].(string) })
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	environment := make([]string, 0, len(names))
	for _, name := range names {
		environment = append(environment, name+"="+values[name])
	}
	encoded, err := json.Marshal(environment)
	if err != nil {
		return nil, "", nil, &ShellProtocolError{Message: "environment snapshot could not be encoded"}
	}
	digest := sha256.Sum256(encoded)
	return environment, hex.EncodeToString(digest[:]), changes, nil
}

func validateShellEnvironmentName(name string) error {
	if name == "" || len(name) > 1024 || strings.ContainsAny(name, "=\x00") || !utf8.ValidString(name) || strings.ContainsRune(name, utf8.RuneError) {
		return &ShellProtocolError{Message: fmt.Sprintf("environment variable name %q is invalid", name)}
	}
	return nil
}

func shellEnvironmentKey(name string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(name)
	}
	return name
}

func platformShell(command string) (string, []string, error) {
	if runtime.GOOS == "windows" {
		path, _, err := resolveShellExecutable("cmd.exe")
		return path, []string{"/d", "/s", "/c", command}, err
	}
	path, _, err := resolveShellExecutable("sh")
	return path, []string{"-c", command}, err
}

type boundedShellBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedShellBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return len(value), nil
	}
	if len(value) > remaining {
		_, _ = buffer.buffer.Write(value[:remaining])
		buffer.overflow = true
		return len(value), nil
	}
	return buffer.buffer.Write(value)
}

func (buffer *boundedShellBuffer) Bytes() []byte {
	return append([]byte(nil), buffer.buffer.Bytes()...)
}

func shellExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}

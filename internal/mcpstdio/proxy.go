// Package mcpstdio implements a policy-enforcing MCP stdio transport proxy.
package mcpstdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/princebabou/Latch/internal/approval"
	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/budget"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/mcpadapter"
	"github.com/princebabou/Latch/internal/policy"
)

const (
	defaultMaxMessageBytes = 4 << 20
	defaultShutdownTimeout = 5 * time.Second
)

var errMessageTooLarge = errors.New("MCP message exceeds configured size limit")

// Options describes one stdio proxy process. The proxy owns the child server's
// lifetime and reserves Output exclusively for newline-delimited JSON-RPC.
type Options struct {
	Policy          policy.Config
	AgentID         string
	Command         string
	Arguments       []string
	Directory       string
	Environment     []string
	MaxMessageBytes int
	ShutdownTimeout time.Duration
	Input           io.Reader
	Output          io.Writer
	ErrorOutput     io.Writer
	AuditLogger     audit.Logger
	ApprovalStore   *approval.Store
	BudgetStore     *budget.Store
	DecisionService *decision.Service
}

// Run starts the upstream MCP server, transparently forwards its entire MCP
// session, and intercepts tools/call before it reaches the server.
func Run(ctx context.Context, options Options) error {
	if strings.TrimSpace(options.Command) == "" {
		return fmt.Errorf("upstream MCP server command is required")
	}
	if err := options.applyDefaults(); err != nil {
		return err
	}

	protocolOut := &lockedWriter{writer: options.Output}
	diagnosticOut := &lockedWriter{writer: options.ErrorOutput}
	command := exec.CommandContext(ctx, options.Command, options.Arguments...)
	command.Dir = options.Directory
	if len(options.Environment) > 0 {
		command.Env = append(os.Environ(), options.Environment...)
	}
	serverInput, err := command.StdinPipe()
	if err != nil {
		return fmt.Errorf("open upstream stdin: %w", err)
	}
	serverOutput, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open upstream stdout: %w", err)
	}
	command.Stderr = diagnosticOut
	if err := command.Start(); err != nil {
		return fmt.Errorf("start upstream MCP server: %w", err)
	}

	inspector, err := mcpadapter.NewInspector(options.DecisionService, "stdio", diagnosticOut)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return fmt.Errorf("configure MCP inspector: %w", err)
	}
	session := mcpadapter.NewSession(options.AgentID)
	clientDone := make(chan error, 1)
	serverDone := make(chan error, 1)
	waitDone := make(chan error, 1)

	go func() {
		clientDone <- pumpClient(options, inspector, session, options.Input, serverInput, protocolOut)
	}()
	go func() {
		serverDone <- pumpServer(serverOutput, protocolOut, options.MaxMessageBytes)
	}()
	go func() { waitDone <- command.Wait() }()

	var firstErr error
	serverFinished, processFinished := false, false
	select {
	case err := <-clientDone:
		firstErr = err
		_ = serverInput.Close()
		if err != nil {
			_ = command.Process.Kill()
		}
	case err := <-serverDone:
		serverFinished = true
		firstErr = err
		_ = serverInput.Close()
		if err != nil {
			_ = command.Process.Kill()
		}
	case err := <-waitDone:
		processFinished = true
		firstErr = normalizeProcessError(err)
		_ = serverInput.Close()
	case <-ctx.Done():
		firstErr = ctx.Err()
		_ = serverInput.Close()
		_ = command.Process.Kill()
	}

	deadline := time.NewTimer(options.ShutdownTimeout)
	defer deadline.Stop()
	for !serverFinished || !processFinished {
		select {
		case err := <-serverDone:
			serverFinished = true
			if firstErr == nil {
				firstErr = err
			}
		case err := <-waitDone:
			processFinished = true
			if firstErr == nil {
				firstErr = normalizeProcessError(err)
			}
		case <-deadline.C:
			_ = command.Process.Kill()
			if firstErr == nil {
				firstErr = fmt.Errorf("upstream MCP server did not shut down within %s", options.ShutdownTimeout)
			}
			deadline.Reset(options.ShutdownTimeout)
		case <-ctx.Done():
			_ = command.Process.Kill()
			if firstErr == nil {
				firstErr = ctx.Err()
			}
		}
	}
	return firstErr
}

func (options *Options) applyDefaults() error {
	if options.MaxMessageBytes <= 0 {
		options.MaxMessageBytes = defaultMaxMessageBytes
	}
	if options.ShutdownTimeout <= 0 {
		options.ShutdownTimeout = defaultShutdownTimeout
	}
	if options.Input == nil {
		options.Input = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if options.ErrorOutput == nil {
		options.ErrorOutput = os.Stderr
	}
	if options.DecisionService == nil {
		service, err := decision.New(options.Policy, options.AuditLogger, options.ApprovalStore, options.BudgetStore)
		if err != nil {
			return err
		}
		options.DecisionService = service
	}
	return nil
}

func pumpClient(options Options, inspector *mcpadapter.Inspector, session *mcpadapter.Session, input io.Reader, serverInput io.Writer, protocolOut *lockedWriter) error {
	reader := bufio.NewReaderSize(input, min(options.MaxMessageBytes, 64<<10))
	for {
		message, err := readMessage(reader, options.MaxMessageBytes)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read MCP client message: %w", err)
		}
		outcome, err := inspector.Inspect(session, message)
		if err != nil {
			return err
		}
		if len(outcome.Response) > 0 {
			if err := writeMessage(protocolOut, outcome.Response); err != nil {
				return fmt.Errorf("write Latch MCP response: %w", err)
			}
		}
		if outcome.Forward {
			if err := writeMessage(serverInput, message); err != nil {
				return fmt.Errorf("forward message to upstream MCP server: %w", err)
			}
		}
	}
}

func pumpServer(input io.Reader, output *lockedWriter, maxMessageBytes int) error {
	reader := bufio.NewReaderSize(input, min(maxMessageBytes, 64<<10))
	for {
		message, err := readMessage(reader, maxMessageBytes)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			_ = writeProtocolError(output, nil, -32603, "Latch: upstream MCP server produced an invalid message")
			return fmt.Errorf("read upstream MCP server message: %w", err)
		}
		if err := mcpadapter.ValidateServerMessage(message); err != nil {
			_ = writeProtocolError(output, nil, -32603, "Latch: upstream MCP server produced invalid protocol data")
			return err
		}
		if err := writeMessage(output, message); err != nil {
			return fmt.Errorf("forward upstream MCP server message: %w", err)
		}
	}
}

func readMessage(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	var message []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(message)+len(fragment) > maxBytes {
			return nil, errMessageTooLarge
		}
		message = append(message, fragment...)
		switch {
		case err == nil:
			return bytes.TrimSuffix(bytes.TrimSuffix(message, []byte("\n")), []byte("\r")), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(message) > 0:
			return message, nil
		default:
			return nil, err
		}
	}
}

func writeMessage(writer io.Writer, message []byte) error {
	if err := writeAll(writer, message); err != nil {
		return err
	}
	return writeAll(writer, []byte{'\n'})
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func writeProtocolError(writer io.Writer, id json.RawMessage, code int, message string) error {
	encoded, err := mcpadapter.ProtocolError(id, code, message)
	if err != nil {
		return err
	}
	return writeMessage(writer, encoded)
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(payload)
}

func normalizeProcessError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("upstream MCP server exited: %w", err)
}

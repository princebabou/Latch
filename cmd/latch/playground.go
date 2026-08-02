package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	playgroundui "github.com/princebabou/Latch/internal/playground"
)

func playgroundCommand(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("playground", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy loaded as the editable baseline")
	listen := fs.String("listen", envOrDefault("LATCH_PLAYGROUND_LISTEN", "127.0.0.1:7073"), "loopback listen address")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "initial trusted identity shown in the lab")
	open := fs.Bool("open", false, "open the playground in the default browser")
	maxRequestBytes := fs.Int64("max-request-bytes", 2<<20, "maximum simulation request size")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "playground does not accept positional arguments")
		return 64
	}
	if err := validatePlaygroundListen(*listen); err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	requiredPolicy := flagProvided(args, "config") || strings.TrimSpace(os.Getenv("LATCH_CONFIG")) != ""
	policyYAML, policyDirectory, sample, err := loadPlaygroundPolicy(*configPath, *agent, requiredPolicy)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	handler, err := playgroundui.New(playgroundui.Options{
		PolicyYAML: policyYAML, PolicyDirectory: policyDirectory,
		AgentID: *agent, MaxRequestBytes: *maxRequestBytes,
	})
	if err != nil {
		fmt.Fprintf(errOut, "configure policy playground: %v\n", err)
		return 1
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(errOut, "start policy playground: %v\n", err)
		return 1
	}
	defer listener.Close()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	ctx, cancel := signalContext()
	defer cancel()
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(listener) }()
	playgroundURL := "http://" + listener.Addr().String()
	if sample {
		fmt.Fprintln(out, "No latch.yaml was found; using an in-memory balanced starter policy.")
	}
	fmt.Fprintf(out, "Latch Policy Lab is ready at %s\n", playgroundURL)
	fmt.Fprintln(out, "Simulation only: no tool, network request, approval, budget, or audit file will be touched.")
	if *open {
		if err := openBrowser(playgroundURL); err != nil {
			fmt.Fprintf(errOut, "Open %s in your browser (%v).\n", playgroundURL, err)
		}
	}
	select {
	case err := <-serveError:
		if err == nil || err == http.ErrServerClosed {
			return 0
		}
		fmt.Fprintf(errOut, "Policy playground stopped: %v\n", err)
		return 1
	case <-ctx.Done():
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			fmt.Fprintf(errOut, "Policy playground shutdown failed: %v\n", err)
			return 1
		}
		return 0
	}
}

func validatePlaygroundListen(address string) error {
	if !loopbackListen(address) {
		return fmt.Errorf("the policy playground is local-only; --listen must use localhost, 127.0.0.0/8, or [::1]")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(port) == "" {
		return fmt.Errorf("--listen must include a valid port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return fmt.Errorf("--listen must include a valid port")
	}
	return nil
}

func loadPlaygroundPolicy(path, agent string, required bool) (content, directory string, sample bool, err error) {
	data, readErr := os.ReadFile(path)
	if readErr == nil {
		absolute, absoluteErr := filepath.Abs(path)
		if absoluteErr != nil {
			return "", "", false, fmt.Errorf("resolve playground policy: %w", absoluteErr)
		}
		return string(data), filepath.Dir(absolute), false, nil
	}
	if !os.IsNotExist(readErr) || required {
		return "", "", false, fmt.Errorf("read playground policy: %w", readErr)
	}
	if strings.TrimSpace(agent) == "" {
		agent = "playground-agent"
	}
	generated, renderErr := renderProfile("balanced", agent)
	if renderErr != nil {
		return "", "", false, renderErr
	}
	directory, directoryErr := os.Getwd()
	if directoryErr != nil {
		return "", "", false, fmt.Errorf("resolve playground directory: %w", directoryErr)
	}
	return generated, directory, true, nil
}

func flagProvided(args []string, name string) bool {
	prefix := "--" + name
	for _, argument := range args {
		if argument == prefix || strings.HasPrefix(argument, prefix+"=") {
			return true
		}
	}
	return false
}

func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		command = exec.Command("open", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

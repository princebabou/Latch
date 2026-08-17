package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/princebabou/Latch/internal/approvalnotify"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/enforcementapi"
	api "github.com/princebabou/Latch/pkg/api/v1"
)

func serve(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	listen := fs.String("listen", envOrDefault("LATCH_API_LISTEN", "127.0.0.1:7070"), "HTTP listen address")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted identity bound to authenticated requests")
	tokenEnvironment := fs.String("token-env", "LATCH_API_TOKEN", "environment variable containing the API bearer token")
	approverTokenEnvironment := fs.String("approver-token-env", "LATCH_APPROVER_TOKEN", "environment variable containing the separate approver token that enables /v1/approvals")
	tlsCertificate := fs.String("tls-cert", "", "TLS certificate file")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	behindTLSProxy := fs.Bool("behind-tls-proxy", false, "confirm TLS terminates at a trusted local reverse proxy")
	maxBodyBytes := fs.Int64("max-body-bytes", 1<<20, "maximum decision request size")
	var allowedOrigins stringSlice
	fs.Var(&allowedOrigins, "allow-origin", "exact browser origin allowed to call the API; repeatable")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "serve does not accept positional arguments")
		return 64
	}
	token := ""
	if name := strings.TrimSpace(*tokenEnvironment); name != "" {
		token = os.Getenv(name)
	}
	approverToken := ""
	if name := strings.TrimSpace(*approverTokenEnvironment); name != "" {
		approverToken = os.Getenv(name)
	}
	if err := validateServeSecurity(*listen, *agent, token, *tlsCertificate, *tlsKey, *behindTLSProxy); err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	if approverToken != "" && token == "" {
		fmt.Fprintln(errOut, "enabling remote approvals requires an API bearer token")
		return 64
	}

	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	notifier, err := approvalnotify.New(config.Approvals.Notify)
	if err != nil {
		fmt.Fprintf(errOut, "configure approval notifier: %v\n", err)
		return 1
	}
	service, err := decision.New(config, nil, nil, nil)
	if err != nil {
		fmt.Fprintf(errOut, "configure decision service: %v\n", err)
		return 1
	}
	handler, err := enforcementapi.New(enforcementapi.Options{
		Service: service, AgentID: *agent, BearerToken: token, ApproverToken: approverToken,
		Notifier: notifier, AllowedOrigins: allowedOrigins, MaxBodyBytes: *maxBodyBytes, Diagnostics: errOut,
	})
	if err != nil {
		fmt.Fprintf(errOut, "configure enforcement API: %v\n", err)
		return 1
	}
	server := &http.Server{
		Addr: *listen, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveError := make(chan error, 1)
	go func() {
		if *tlsCertificate != "" {
			serveError <- server.ListenAndServeTLS(*tlsCertificate, *tlsKey)
			return
		}
		serveError <- server.ListenAndServe()
	}()
	scheme := "http"
	if *tlsCertificate != "" {
		scheme = "https"
	}
	fmt.Fprintf(out, "Latch enforcement API %s listening at %s://%s/v1/decisions\n", api.APIVersion, scheme, *listen)
	select {
	case err := <-serveError:
		if err == http.ErrServerClosed {
			return 0
		}
		fmt.Fprintf(errOut, "Latch enforcement API stopped: %v\n", err)
		return 1
	case <-ctx.Done():
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			fmt.Fprintf(errOut, "Latch enforcement API shutdown failed: %v\n", err)
			return 1
		}
		return 0
	}
}

func loopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateServeSecurity(listen, agent, token, certificate, key string, behindTLSProxy bool) error {
	if (certificate == "") != (key == "") {
		return fmt.Errorf("--tls-cert and --tls-key must be provided together")
	}
	if strings.TrimSpace(agent) != "" && strings.TrimSpace(token) == "" {
		return fmt.Errorf("a trusted --agent binding requires a non-empty bearer token environment variable")
	}
	if loopbackListen(listen) {
		return nil
	}
	if strings.TrimSpace(token) == "" || strings.TrimSpace(agent) == "" {
		return fmt.Errorf("non-loopback serving requires both --agent and a non-empty bearer token environment variable")
	}
	if certificate == "" && !behindTLSProxy {
		return fmt.Errorf("non-loopback serving requires TLS or --behind-tls-proxy")
	}
	return nil
}

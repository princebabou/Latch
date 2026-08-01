package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/princebabou/Latch/internal/apiproxy"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/policy"
)

func proxyAPI(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("proxy-api", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	upstream := fs.String("upstream", "", "fixed upstream HTTP API base URL")
	listen := fs.String("listen", envOrDefault("LATCH_HTTP_LISTEN", "127.0.0.1:7072"), "HTTP listen address")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted identity bound to authenticated requests")
	tokenEnvironment := fs.String("token-env", "LATCH_HTTP_TOKEN", "environment variable containing the gateway token")
	authHeader := fs.String("auth-header", "X-Latch-Token", "request header carrying the Latch gateway token")
	upstreamTokenEnvironment := fs.String("upstream-token-env", "LATCH_HTTP_UPSTREAM_TOKEN", "optional environment variable containing an upstream bearer token")
	forwardSensitiveHeaders := fs.Bool("forward-sensitive-headers", false, "forward agent-supplied credentials and cookies for explicit policy evaluation")
	allowHTTPUpstream := fs.Bool("allow-http-upstream", false, "allow cleartext HTTP to a non-loopback upstream")
	tlsCertificate := fs.String("tls-cert", "", "TLS certificate file")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	behindTLSProxy := fs.Bool("behind-tls-proxy", false, "confirm TLS terminates at a trusted local reverse proxy")
	maxBodyBytes := fs.Int64("max-body-bytes", 4<<20, "maximum API request body size")
	var allowedOrigins stringSlice
	var upstreamHeaderEnvironments stringSlice
	fs.Var(&allowedOrigins, "allow-origin", "exact browser origin allowed to call the gateway; repeatable")
	fs.Var(&upstreamHeaderEnvironments, "upstream-header-env", "operator header in Header=ENV_VAR form; repeatable")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "proxy-api does not accept positional arguments")
		return 64
	}
	if strings.TrimSpace(*upstream) == "" {
		fmt.Fprintln(errOut, "--upstream is required")
		return 64
	}
	if err := validateUpstreamSecurity(*upstream, *allowHTTPUpstream); err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	token := environmentValue(*tokenEnvironment)
	if err := validateServeSecurity(*listen, *agent, token, *tlsCertificate, *tlsKey, *behindTLSProxy); err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	upstreamHeaders, err := parseUpstreamHeaderEnvironments(upstreamHeaderEnvironments)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 64
	}
	if upstreamToken := environmentValue(*upstreamTokenEnvironment); upstreamToken != "" {
		if upstreamHeaders.Get("Authorization") != "" {
			fmt.Fprintln(errOut, "upstream Authorization is configured by both --upstream-token-env and --upstream-header-env")
			return 64
		}
		upstreamHeaders.Set("Authorization", "Bearer "+upstreamToken)
	}

	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	agentID := strings.TrimSpace(*agent)
	if canonical, known := policy.CanonicalAgentID(config, agentID); known {
		agentID = canonical
	}
	if config.Identity.RequireVerified && agentID == "" {
		fmt.Fprintln(errOut, "this policy requires --agent or LATCH_AGENT")
		return 64
	}
	if config.Identity.EnforceCapabilities {
		if _, known := policy.CanonicalAgentID(config, agentID); !known {
			fmt.Fprintf(errOut, "agent %q is not registered for capability enforcement\n", agentID)
			return 64
		}
	}
	service, err := decision.New(config, nil, nil, nil)
	if err != nil {
		fmt.Fprintf(errOut, "configure decision service: %v\n", err)
		return 1
	}
	handler, err := apiproxy.New(apiproxy.Options{
		Service: service, AgentID: agentID, UpstreamURL: *upstream,
		GatewayToken: token, GatewayAuthHeader: *authHeader, UpstreamHeaders: upstreamHeaders,
		ForwardSensitiveHeaders: *forwardSensitiveHeaders, AllowedOrigins: allowedOrigins,
		MaxBodyBytes: *maxBodyBytes, Diagnostics: errOut,
	})
	if err != nil {
		fmt.Fprintf(errOut, "configure HTTP/API proxy: %v\n", err)
		return 1
	}
	server := &http.Server{
		Addr: *listen, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 1 << 20,
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
	fmt.Fprintf(out, "Latch HTTP/API gateway listening at %s://%s -> %s\n", scheme, *listen, *upstream)
	select {
	case err := <-serveError:
		if err == http.ErrServerClosed {
			return 0
		}
		fmt.Fprintf(errOut, "Latch HTTP/API gateway stopped: %v\n", err)
		return 1
	case <-ctx.Done():
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			fmt.Fprintf(errOut, "Latch HTTP/API gateway shutdown failed: %v\n", err)
			return 1
		}
		_ = handler.Shutdown(shutdownContext)
		return 0
	}
}

func parseUpstreamHeaderEnvironments(values []string) (http.Header, error) {
	headers := make(http.Header)
	for _, item := range values {
		name, environment, found := strings.Cut(item, "=")
		name, environment = strings.TrimSpace(name), strings.TrimSpace(environment)
		if !found || name == "" || !validEnvironmentName(environment) {
			return nil, fmt.Errorf("invalid --upstream-header-env %q; expected Header=ENV_VAR", item)
		}
		value := os.Getenv(environment)
		if value == "" {
			return nil, fmt.Errorf("environment variable %s configured for upstream header %s is empty", environment, name)
		}
		if headers.Get(name) != "" {
			return nil, fmt.Errorf("upstream header %s is configured more than once", name)
		}
		headers.Set(name, value)
	}
	return headers, nil
}

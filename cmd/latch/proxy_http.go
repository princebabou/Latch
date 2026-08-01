package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/mcphttp"
	"github.com/princebabou/Latch/internal/policy"
)

func proxyHTTP(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("proxy-http", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configPath := fs.String("config", defaultConfigFromEnv(), "YAML policy file")
	upstream := fs.String("upstream", "", "upstream MCP Streamable HTTP endpoint")
	listen := fs.String("listen", envOrDefault("LATCH_MCP_LISTEN", "127.0.0.1:7071"), "HTTP listen address")
	endpointPath := fs.String("path", "/mcp", "public MCP endpoint path")
	agent := fs.String("agent", envOrDefault("LATCH_AGENT", ""), "trusted identity bound to authenticated requests")
	tokenEnvironment := fs.String("token-env", "LATCH_MCP_TOKEN", "environment variable containing the proxy bearer token")
	upstreamTokenEnvironment := fs.String("upstream-token-env", "LATCH_MCP_UPSTREAM_TOKEN", "environment variable containing the upstream bearer token")
	allowHTTPUpstream := fs.Bool("allow-http-upstream", false, "allow cleartext HTTP to a non-loopback upstream")
	tlsCertificate := fs.String("tls-cert", "", "TLS certificate file")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	behindTLSProxy := fs.Bool("behind-tls-proxy", false, "confirm TLS terminates at a trusted local reverse proxy")
	maxMessageBytes := fs.Int64("max-message-bytes", 4<<20, "maximum MCP JSON-RPC request size")
	maxSessions := fs.Int("max-sessions", 10_000, "maximum remembered upstream MCP sessions")
	sessionTTL := fs.Duration("session-ttl", 24*time.Hour, "inactive MCP session identity lifetime")
	var allowedOrigins stringSlice
	fs.Var(&allowedOrigins, "allow-origin", "exact browser origin allowed to call the MCP endpoint; repeatable")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "proxy-http does not accept positional arguments")
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
	upstreamToken := environmentValue(*upstreamTokenEnvironment)
	if err := validateServeSecurity(*listen, *agent, token, *tlsCertificate, *tlsKey, *behindTLSProxy); err != nil {
		fmt.Fprintln(errOut, err)
		return 64
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
	handler, err := mcphttp.New(mcphttp.Options{
		Service: service, AgentID: agentID, UpstreamURL: *upstream,
		BearerToken: token, UpstreamBearerToken: upstreamToken,
		AllowedOrigins: allowedOrigins, EndpointPath: *endpointPath,
		MaxBodyBytes: *maxMessageBytes, SessionLimit: *maxSessions,
		SessionTTL: *sessionTTL, Diagnostics: errOut,
	})
	if err != nil {
		fmt.Fprintf(errOut, "configure MCP Streamable HTTP proxy: %v\n", err)
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
	fmt.Fprintf(out, "Latch MCP Streamable HTTP proxy listening at %s://%s%s -> %s\n", scheme, *listen, *endpointPath, *upstream)
	select {
	case err := <-serveError:
		if err == http.ErrServerClosed {
			return 0
		}
		fmt.Fprintf(errOut, "Latch MCP Streamable HTTP proxy stopped: %v\n", err)
		return 1
	case <-ctx.Done():
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			fmt.Fprintf(errOut, "Latch MCP Streamable HTTP proxy shutdown failed: %v\n", err)
			return 1
		}
		_ = handler.Shutdown(shutdownContext)
		return 0
	}
}

func environmentValue(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return os.Getenv(name)
}

func validateUpstreamSecurity(raw string, allowHTTP bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("--upstream must be an absolute HTTP or HTTPS URL")
	}
	if parsed.Scheme == "https" || loopbackHost(parsed.Hostname()) || allowHTTP {
		return nil
	}
	return fmt.Errorf("cleartext non-loopback upstream requires --allow-http-upstream")
}

func loopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

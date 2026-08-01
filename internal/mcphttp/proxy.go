// Package mcphttp implements a policy-enforcing MCP Streamable HTTP proxy.
package mcphttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/mcpadapter"
)

const (
	defaultEndpointPath = "/mcp"
	defaultMaxBodyBytes = 4 << 20
	defaultSessionLimit = 10_000
	defaultSessionTTL   = 24 * time.Hour
)

// Options configures one MCP Streamable HTTP security boundary.
type Options struct {
	Service             *decision.Service
	AgentID             string
	UpstreamURL         string
	BearerToken         string
	UpstreamBearerToken string
	AllowedOrigins      []string
	EndpointPath        string
	MaxBodyBytes        int64
	SessionLimit        int
	SessionTTL          time.Duration
	Diagnostics         io.Writer
	HTTPClient          *http.Client
	Now                 func() time.Time
}

type Handler struct {
	inspector      *mcpadapter.Inspector
	agentID        string
	upstream       *url.URL
	endpointPath   string
	maxBodyBytes   int64
	client         *http.Client
	bearerHash     [sha256.Size]byte
	requireBearer  bool
	upstreamToken  string
	allowedOrigins map[string]struct{}
	sessions       *sessionCache
	diagnostics    io.Writer
}

func New(options Options) (*Handler, error) {
	if options.Service == nil {
		return nil, fmt.Errorf("decision service is required")
	}
	upstream, err := parseUpstream(options.UpstreamURL)
	if err != nil {
		return nil, err
	}
	if options.EndpointPath == "" {
		options.EndpointPath = defaultEndpointPath
	}
	if !validEndpointPath(options.EndpointPath) {
		return nil, fmt.Errorf("endpoint path must be an absolute path without a query or fragment")
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = defaultMaxBodyBytes
	}
	if options.MaxBodyBytes < 1024 || options.MaxBodyBytes > 16<<20 {
		return nil, fmt.Errorf("max body size must be between 1024 and 16777216 bytes")
	}
	if options.SessionLimit <= 0 {
		options.SessionLimit = defaultSessionLimit
	}
	if options.SessionLimit > 1_000_000 {
		return nil, fmt.Errorf("session limit cannot exceed 1000000")
	}
	if options.SessionTTL <= 0 {
		options.SessionTTL = defaultSessionTTL
	}
	if options.SessionTTL < time.Minute || options.SessionTTL > 30*24*time.Hour {
		return nil, fmt.Errorf("session TTL must be between one minute and 720 hours")
	}
	if options.Diagnostics == nil {
		options.Diagnostics = io.Discard
	}
	inspector, err := mcpadapter.NewInspector(options.Service, "streamable-http", options.Diagnostics)
	if err != nil {
		return nil, err
	}
	origins := make(map[string]struct{}, len(options.AllowedOrigins))
	for _, origin := range options.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if !validOrigin(origin) {
			return nil, fmt.Errorf("allowed origin %q must be an explicit HTTP or HTTPS origin without a path", origin)
		}
		origins[origin] = struct{}{}
	}
	client := options.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ResponseHeaderTimeout = 2 * time.Minute
		client = &http.Client{Transport: transport}
	} else {
		clone := *client
		client = &clone
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

	handler := &Handler{
		inspector: inspector, agentID: strings.TrimSpace(options.AgentID), upstream: upstream,
		endpointPath: options.EndpointPath, maxBodyBytes: options.MaxBodyBytes, client: client,
		upstreamToken: strings.TrimSpace(options.UpstreamBearerToken), allowedOrigins: origins,
		sessions:    newSessionCache(options.SessionLimit, options.SessionTTL, options.Now),
		diagnostics: options.Diagnostics,
	}
	if options.BearerToken != "" {
		if len(options.BearerToken) < 32 || len(options.BearerToken) > 4096 {
			return nil, fmt.Errorf("bearer token must contain between 32 and 4096 bytes")
		}
		handler.requireBearer = true
		handler.bearerHash = sha256.Sum256([]byte(options.BearerToken))
	}
	if len(handler.upstreamToken) > 16<<10 {
		return nil, fmt.Errorf("upstream bearer token cannot exceed 16384 bytes")
	}
	return handler, nil
}

func parseUpstream(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("upstream URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("upstream URL cannot contain credentials, a query, or a fragment")
	}
	return parsed, nil
}

func validEndpointPath(path string) bool {
	parsed, err := url.ParseRequestURI(path)
	return err == nil && strings.HasPrefix(path, "/") && parsed.Path == path && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validOrigin(origin string) bool {
	if origin == "" || origin == "*" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return false
	}
	return parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	secureHeaders(response)
	if request.URL.Path != h.endpointPath {
		h.writeHTTPError(response, http.StatusNotFound, -32601, "Latch: MCP endpoint not found")
		return
	}
	if request.URL.RawQuery != "" {
		h.writeHTTPError(response, http.StatusBadRequest, -32600, "Latch: MCP endpoint does not accept query parameters")
		return
	}
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin != "" {
		if _, allowed := h.allowedOrigins[origin]; !allowed {
			h.writeHTTPError(response, http.StatusForbidden, -32000, "Latch: origin is not allowed")
			return
		}
		setCORS(response, origin)
	}
	if request.Method == http.MethodOptions {
		response.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		response.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID")
		response.Header().Set("Access-Control-Expose-Headers", "MCP-Session-Id")
		response.Header().Set("Access-Control-Max-Age", "600")
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost && request.Method != http.MethodDelete {
		response.Header().Set("Allow", "GET, POST, DELETE, OPTIONS")
		h.writeHTTPError(response, http.StatusMethodNotAllowed, -32600, "Latch: unsupported MCP transport method")
		return
	}
	if !h.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="latch-mcp"`)
		h.writeHTTPError(response, http.StatusUnauthorized, -32001, "Latch: valid bearer authentication is required")
		return
	}
	sessionID, err := requestSessionID(request.Header)
	if err != nil {
		h.writeHTTPError(response, http.StatusBadRequest, -32600, "Latch: invalid MCP-Session-Id header")
		return
	}

	var body []byte
	var outcome mcpadapter.Outcome
	session := h.session(sessionID)
	if request.Method == http.MethodPost {
		if !hasMediaType(request.Header.Get("Content-Type"), "application/json") {
			h.writeHTTPError(response, http.StatusUnsupportedMediaType, -32600, "Latch: MCP POST requests require application/json")
			return
		}
		if !accepts(request.Header.Get("Accept"), "application/json") || !accepts(request.Header.Get("Accept"), "text/event-stream") {
			h.writeHTTPError(response, http.StatusNotAcceptable, -32600, "Latch: Accept must include application/json and text/event-stream")
			return
		}
		body, err = h.readBody(response, request)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				h.writeHTTPError(response, http.StatusRequestEntityTooLarge, -32600, "Latch: MCP message exceeds the configured size limit")
				return
			}
			h.writeHTTPError(response, http.StatusBadRequest, -32700, "Latch: could not read MCP message")
			return
		}
		if _, err := mcpadapter.DecodeObject(body); err != nil {
			encoded, _ := mcpadapter.ProtocolError(nil, -32700, "Latch: invalid JSON-RPC message")
			h.writeJSONRPC(response, http.StatusBadRequest, encoded)
			return
		}
		outcome, err = h.inspector.Inspect(session, body)
		if err != nil {
			h.writeHTTPError(response, http.StatusInternalServerError, -32603, "Latch: enforcement adapter failed closed")
			return
		}
		if !outcome.Forward {
			h.writeJSONRPC(response, http.StatusOK, outcome.Response)
			return
		}
	}
	h.forward(response, request, body, sessionID, session, outcome.Method, origin)
}

func (h *Handler) readBody(response http.ResponseWriter, request *http.Request) ([]byte, error) {
	if request.ContentLength > h.maxBodyBytes {
		return nil, &http.MaxBytesError{Limit: h.maxBodyBytes}
	}
	request.Body = http.MaxBytesReader(response, request.Body, h.maxBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (h *Handler) session(id string) *mcpadapter.Session {
	if id != "" {
		if session, exists := h.sessions.get(id); exists {
			return session
		}
	}
	return mcpadapter.NewSession(h.agentID)
}

func (h *Handler) forward(response http.ResponseWriter, request *http.Request, body []byte, sessionID string, session *mcpadapter.Session, method, origin string) {
	upstreamRequest, err := http.NewRequestWithContext(request.Context(), request.Method, h.upstream.String(), bytes.NewReader(body))
	if err != nil {
		h.writeHTTPError(response, http.StatusBadGateway, -32603, "Latch: could not construct upstream MCP request")
		return
	}
	copyRequestHeaders(upstreamRequest.Header, request.Header)
	if h.requireBearer {
		upstreamRequest.Header.Del("Authorization")
	}
	if h.upstreamToken != "" {
		upstreamRequest.Header.Set("Authorization", "Bearer "+h.upstreamToken)
	}
	upstreamRequest.Host = h.upstream.Host
	upstreamResponse, err := h.client.Do(upstreamRequest)
	if err != nil {
		fmt.Fprintln(h.diagnostics, "Latch: upstream MCP server unavailable; request failed closed")
		h.writeHTTPError(response, http.StatusBadGateway, -32603, "Latch: upstream MCP server is unavailable")
		return
	}
	defer upstreamResponse.Body.Close()
	if upstreamResponse.StatusCode >= 300 && upstreamResponse.StatusCode < 400 {
		h.writeHTTPError(response, http.StatusBadGateway, -32603, "Latch: upstream MCP redirects are forbidden")
		return
	}
	upstreamSessionID, sessionErr := responseSessionID(upstreamResponse.Header)
	if sessionErr != nil {
		h.writeHTTPError(response, http.StatusBadGateway, -32603, "Latch: upstream returned an invalid MCP-Session-Id")
		return
	}
	if method == "initialize" && upstreamSessionID != "" {
		if !h.sessions.put(upstreamSessionID, session) {
			h.writeHTTPError(response, http.StatusBadGateway, -32603, "Latch: upstream reused an active MCP session ID")
			return
		}
	}
	if upstreamResponse.StatusCode == http.StatusNotFound && sessionID != "" {
		h.sessions.remove(sessionID)
	}
	if request.Method == http.MethodDelete && sessionID != "" && upstreamResponse.StatusCode >= 200 && upstreamResponse.StatusCode < 300 {
		h.sessions.remove(sessionID)
	}

	copyResponseHeaders(response.Header(), upstreamResponse.Header)
	if origin != "" {
		setCORS(response, origin)
	}
	secureHeaders(response)
	response.WriteHeader(upstreamResponse.StatusCode)
	flush(response)
	buffer := make([]byte, 32<<10)
	for {
		read, readErr := upstreamResponse.Body.Read(buffer)
		if read > 0 {
			if _, writeErr := response.Write(buffer[:read]); writeErr != nil {
				return
			}
			flush(response)
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				fmt.Fprintln(h.diagnostics, "Latch: upstream MCP response stream ended unexpectedly")
			}
			return
		}
	}
}

func (h *Handler) authorized(header string) bool {
	if !h.requireBearer {
		return true
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return false
	}
	actual := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return subtle.ConstantTimeCompare(actual[:], h.bearerHash[:]) == 1
}

func (h *Handler) writeHTTPError(response http.ResponseWriter, status, code int, message string) {
	encoded, err := mcpadapter.ProtocolError(nil, code, message)
	if err != nil {
		http.Error(response, "Latch adapter error", http.StatusInternalServerError)
		return
	}
	h.writeJSONRPC(response, status, encoded)
}

func (h *Handler) writeJSONRPC(response http.ResponseWriter, status int, encoded []byte) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func hasMediaType(header, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(header)
	return err == nil && strings.EqualFold(mediaType, expected)
}

func accepts(header, expected string) bool {
	for _, item := range strings.Split(header, ",") {
		mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(item))
		if err == nil && strings.EqualFold(mediaType, expected) {
			quality := 1.0
			if rawQuality, exists := parameters["q"]; exists {
				quality, err = strconv.ParseFloat(rawQuality, 64)
			}
			if err == nil && quality > 0 && quality <= 1 {
				return true
			}
		}
	}
	return false
}

func requestSessionID(header http.Header) (string, error) {
	return oneSessionID(header.Values("MCP-Session-Id"))
}

func responseSessionID(header http.Header) (string, error) {
	return oneSessionID(header.Values("MCP-Session-Id"))
}

func oneSessionID(values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || !validSessionID(values[0]) {
		return "", fmt.Errorf("invalid MCP session ID")
	}
	return values[0], nil
}

func validSessionID(value string) bool {
	if len(value) == 0 || len(value) > 1024 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func copyRequestHeaders(destination, source http.Header) {
	copyHeaders(destination, source)
	destination.Del("Forwarded")
	destination.Del("X-Forwarded-For")
	destination.Del("X-Forwarded-Host")
	destination.Del("X-Forwarded-Proto")
}

func copyResponseHeaders(destination, source http.Header) {
	copyHeaders(destination, source)
	for key := range destination {
		if strings.HasPrefix(strings.ToLower(key), "access-control-") {
			destination.Del(key)
		}
	}
}

func copyHeaders(destination, source http.Header) {
	connectionHeaders := make(map[string]struct{})
	for _, connection := range source.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			connectionHeaders[http.CanonicalHeaderKey(strings.TrimSpace(name))] = struct{}{}
		}
	}
	for key, values := range source {
		canonical := http.CanonicalHeaderKey(key)
		if hopByHop(canonical) {
			continue
		}
		if _, excluded := connectionHeaders[canonical]; excluded {
			continue
		}
		for _, value := range values {
			destination.Add(canonical, value)
		}
	}
}

func hopByHop(header string) bool {
	switch header {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func setCORS(response http.ResponseWriter, origin string) {
	response.Header().Set("Access-Control-Allow-Origin", origin)
	response.Header().Set("Access-Control-Expose-Headers", "MCP-Session-Id")
	for _, value := range response.Header().Values("Vary") {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), "Origin") {
				return
			}
		}
	}
	response.Header().Add("Vary", "Origin")
}

func secureHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
}

func flush(response http.ResponseWriter) {
	if flusher, ok := response.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Shutdown closes idle upstream connections during graceful process shutdown.
func (h *Handler) Shutdown(_ context.Context) error {
	if transport, ok := h.client.Transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// Compile-time check that Handler remains directly mountable in net/http.
var _ http.Handler = (*Handler)(nil)

// Package apiproxy implements a policy-enforcing reverse proxy for HTTP APIs.
package apiproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/princebabou/Latch/internal/audit"
	"github.com/princebabou/Latch/internal/decision"
	"github.com/princebabou/Latch/internal/normalize"
	"github.com/princebabou/Latch/internal/risk"
	"github.com/princebabou/Latch/internal/strictjson"
	"github.com/princebabou/Latch/pkg/models"
)

const (
	defaultMaxBodyBytes = 4 << 20
	inspectionBodyLimit = 256 << 10
	maxPathBytes        = 8 << 10
	maxQueryBytes       = 16 << 10
	defaultAuthHeader   = "X-Latch-Token"
	proxyMediaType      = "application/vnd.latch.proxy.v1+json"
)

// Options configures one generic HTTP/API enforcement boundary.
type Options struct {
	Service                 *decision.Service
	AgentID                 string
	UpstreamURL             string
	GatewayToken            string
	GatewayAuthHeader       string
	UpstreamHeaders         http.Header
	ForwardSensitiveHeaders bool
	AllowedOrigins          []string
	MaxBodyBytes            int64
	Diagnostics             io.Writer
	HTTPClient              *http.Client
}

// Handler evaluates every request before forwarding it to a fixed upstream.
type Handler struct {
	service                 *decision.Service
	agentID                 string
	upstream                *url.URL
	maxBodyBytes            int64
	client                  *http.Client
	authHeader              string
	tokenHash               [sha256.Size]byte
	requireToken            bool
	upstreamHeaders         http.Header
	forwardSensitiveHeaders bool
	allowedOrigins          map[string]struct{}
	diagnostics             io.Writer
}

// New constructs a fail-closed HTTP/API reverse proxy.
func New(options Options) (*Handler, error) {
	if options.Service == nil {
		return nil, fmt.Errorf("decision service is required")
	}
	upstream, err := parseUpstream(options.UpstreamURL)
	if err != nil {
		return nil, err
	}
	if err := validatePath(upstream.EscapedPath()); err != nil {
		return nil, fmt.Errorf("unsafe upstream base path: %w", err)
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = defaultMaxBodyBytes
	}
	if options.MaxBodyBytes < 1024 || options.MaxBodyBytes > 16<<20 {
		return nil, fmt.Errorf("max body size must be between 1024 and 16777216 bytes")
	}
	if options.Diagnostics == nil {
		options.Diagnostics = io.Discard
	}
	authHeader := strings.TrimSpace(options.GatewayAuthHeader)
	if authHeader == "" {
		authHeader = defaultAuthHeader
	}
	if !validHeaderName(authHeader) || hopByHop(http.CanonicalHeaderKey(authHeader)) {
		return nil, fmt.Errorf("gateway authentication header is invalid")
	}
	authHeader = http.CanonicalHeaderKey(authHeader)

	origins := make(map[string]struct{}, len(options.AllowedOrigins))
	for _, origin := range options.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if !validOrigin(origin) {
			return nil, fmt.Errorf("allowed origin %q must be an explicit HTTP or HTTPS origin without a path", origin)
		}
		origins[origin] = struct{}{}
	}
	staticHeaders := make(http.Header, len(options.UpstreamHeaders))
	for name, values := range options.UpstreamHeaders {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if !validHeaderName(canonical) || forbiddenStaticHeader(canonical, authHeader) {
			return nil, fmt.Errorf("upstream header %q cannot be set by the gateway", name)
		}
		for _, value := range values {
			if len(value) > 16<<10 || strings.ContainsAny(value, "\r\n") {
				return nil, fmt.Errorf("upstream header %q has an invalid value", name)
			}
			staticHeaders.Add(canonical, value)
		}
	}

	client := options.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ResponseHeaderTimeout = 2 * time.Minute
		transport.MaxResponseHeaderBytes = 1 << 20
		client = &http.Client{Transport: transport}
	} else {
		clone := *client
		client = &clone
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

	handler := &Handler{
		service: options.Service, agentID: strings.TrimSpace(options.AgentID), upstream: upstream,
		maxBodyBytes: options.MaxBodyBytes, client: client, authHeader: authHeader,
		upstreamHeaders: staticHeaders, forwardSensitiveHeaders: options.ForwardSensitiveHeaders,
		allowedOrigins: origins, diagnostics: options.Diagnostics,
	}
	if options.GatewayToken != "" {
		if len(options.GatewayToken) < 32 || len(options.GatewayToken) > 4096 {
			return nil, fmt.Errorf("gateway token must contain between 32 and 4096 bytes")
		}
		handler.requireToken = true
		handler.tokenHash = sha256.Sum256([]byte(options.GatewayToken))
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

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin != "" {
		if _, allowed := h.allowedOrigins[origin]; !allowed {
			h.writeError(response, http.StatusForbidden, "origin_not_allowed", "This browser origin is not allowed by Latch.", nil)
			return
		}
		setCORS(response, origin)
	}
	if isPreflight(request) {
		h.preflight(response, request, origin)
		return
	}
	if !h.authorized(request.Header.Values(h.authHeader)) {
		response.Header().Set("WWW-Authenticate", `LatchToken realm="latch-http"`)
		h.writeError(response, http.StatusUnauthorized, "authentication_required", "A valid Latch gateway token is required.", nil)
		return
	}
	if request.Method == http.MethodConnect || request.Method == http.MethodTrace {
		response.Header().Set("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
		h.writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "Latch does not proxy CONNECT or TRACE.", nil)
		return
	}
	if err := validateRequestHeaders(request.Header); err != nil {
		h.writeError(response, http.StatusRequestHeaderFieldsTooLarge, "ambiguous_headers", "Request headers are oversized or ambiguous and were blocked before forwarding.", nil)
		return
	}
	if strings.TrimSpace(request.Header.Get("Content-Encoding")) != "" && !strings.EqualFold(strings.TrimSpace(request.Header.Get("Content-Encoding")), "identity") {
		h.writeError(response, http.StatusUnsupportedMediaType, "content_encoding_not_supported", "Compressed request bodies are rejected because they cannot be inspected safely.", nil)
		return
	}
	destination, actionURL, err := h.destination(request.URL)
	if err != nil {
		h.writeError(response, http.StatusBadRequest, "invalid_destination", "The request path or query is not safe to proxy.", nil)
		return
	}
	body, err := h.readBody(response, request)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.writeError(response, http.StatusRequestEntityTooLarge, "body_too_large", "The request body exceeds the configured Latch limit.", nil)
			return
		}
		h.writeError(response, http.StatusBadRequest, "body_read_failed", "Latch could not safely read the request body.", nil)
		return
	}

	forwardHeaders, inspectionHeaders, stripped := h.requestHeaders(request.Header)
	arguments := map[string]any{"method": strings.ToUpper(request.Method), "url": actionURL.String()}
	if len(inspectionHeaders) > 0 {
		arguments["headers"] = inspectionHeaders
	}
	if len(stripped) > 0 {
		arguments["stripped_headers"] = stripped
	}
	if err := inspectBody(arguments, forwardHeaders.Get("Content-Type"), body); err != nil {
		h.writeError(response, http.StatusBadRequest, "ambiguous_body", "The request body is malformed or ambiguous and was blocked before forwarding.", nil)
		return
	}
	action, err := normalize.Action(normalize.Request{
		AgentID: h.agentID, Tool: "http.request", Arguments: arguments,
		Metadata: map[string]any{
			"protocol": "http", "adapter": "reverse-proxy", "identity_verified": h.agentID != "", "identity_source": "operator_config",
		},
	})
	if err != nil {
		h.writeError(response, http.StatusInternalServerError, "normalization_failed", "Latch could not safely normalize this request.", nil)
		return
	}
	identity := models.IdentityContext{ID: h.agentID, Verified: h.agentID != "", Source: "operator_config"}
	result := h.service.Decide(action, identity)
	if diagnostic := decision.Diagnostic(result); diagnostic != "" {
		fmt.Fprintln(h.diagnostics, diagnostic)
	}
	if h.service.Policy.Audit.Terminal {
		fmt.Fprintln(h.diagnostics, audit.Terminal(result.Event))
	}
	if result.Assessment.Decision != models.DecisionAllow {
		h.writeDecision(response, result)
		return
	}
	h.forward(response, request, destination, forwardHeaders, body, origin)
}

func (h *Handler) destination(incoming *url.URL) (*url.URL, *url.URL, error) {
	escapedPath := incoming.EscapedPath()
	if err := validatePath(escapedPath); err != nil {
		return nil, nil, err
	}
	if len(incoming.RawQuery) > maxQueryBytes {
		return nil, nil, fmt.Errorf("query is too long")
	}
	query, err := url.ParseQuery(incoming.RawQuery)
	if err != nil {
		return nil, nil, err
	}
	destination := *h.upstream
	basePath := strings.TrimSuffix(h.upstream.Path, "/")
	requestPath := "/" + strings.TrimPrefix(incoming.Path, "/")
	destination.Path = basePath + requestPath
	if destination.Path == "" {
		destination.Path = "/"
	}
	baseRaw := strings.TrimSuffix(h.upstream.EscapedPath(), "/")
	requestRaw := "/" + strings.TrimPrefix(escapedPath, "/")
	joinedRaw := baseRaw + requestRaw
	if joinedRaw != destination.EscapedPath() {
		destination.RawPath = joinedRaw
	} else {
		destination.RawPath = ""
	}
	destination.RawQuery = incoming.RawQuery

	actionURL := destination
	for key, values := range query {
		if risk.IsSensitiveName(key) {
			for index := range values {
				values[index] = "[REDACTED]"
			}
			query[key] = values
		}
	}
	actionURL.RawQuery = query.Encode()
	return &destination, &actionURL, nil
}

func validatePath(escaped string) error {
	if escaped == "" {
		escaped = "/"
	}
	if len(escaped) > maxPathBytes || !strings.HasPrefix(escaped, "/") {
		return fmt.Errorf("invalid path")
	}
	lower := strings.ToLower(escaped)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") || strings.Contains(lower, "%25") {
		return fmt.Errorf("encoded path separator or NUL is forbidden")
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil || !utf8.ValidString(decoded) || strings.ContainsAny(decoded, "\\\x00") || strings.HasPrefix(decoded, "//") {
		return fmt.Errorf("invalid encoded path")
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("dot segments are forbidden")
		}
	}
	return nil
}

func (h *Handler) readBody(response http.ResponseWriter, request *http.Request) ([]byte, error) {
	if request.ContentLength > h.maxBodyBytes {
		return nil, &http.MaxBytesError{Limit: h.maxBodyBytes}
	}
	request.Body = http.MaxBytesReader(response, request.Body, h.maxBodyBytes)
	return io.ReadAll(request.Body)
}

func inspectBody(arguments map[string]any, contentType string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	mediaType := ""
	if strings.TrimSpace(contentType) != "" {
		var err error
		mediaType, _, err = mime.ParseMediaType(contentType)
		if err != nil {
			return err
		}
		mediaType = strings.ToLower(mediaType)
	}
	digest := sha256.Sum256(body)
	metadata := map[string]any{
		"bytes": len(body), "sha256": hex.EncodeToString(digest[:]), "content_type": mediaType,
	}
	if len(body) > inspectionBodyLimit {
		arguments["body_metadata"] = metadata
		arguments["body_inspected"] = false
		return nil
	}
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		var value any
		if err := strictjson.Decode(body, &value); err != nil {
			return err
		}
		arguments["body"] = value
	case mediaType == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return err
		}
		form := make(map[string]any, len(values))
		for key, entries := range values {
			if len(entries) == 1 {
				form[key] = entries[0]
			} else {
				form[key] = entries
			}
		}
		arguments["body"] = form
	case strings.HasPrefix(mediaType, "text/") || mediaType == "":
		if !utf8.Valid(body) {
			arguments["body_inspected"] = false
			return nil
		}
		arguments["body"] = string(body)
	default:
		arguments["body_metadata"] = metadata
		arguments["body_inspected"] = false
	}
	return nil
}

func (h *Handler) requestHeaders(source http.Header) (http.Header, map[string]any, []string) {
	forwarded := make(http.Header)
	inspection := make(map[string]any)
	var stripped []string
	connectionHeaders := connectionHeaderNames(source)
	for name, values := range source {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == h.authHeader || hopByHop(canonical) {
			continue
		}
		if _, connected := connectionHeaders[canonical]; connected {
			continue
		}
		if strings.HasPrefix(strings.ToLower(canonical), "x-forwarded-") || strings.EqualFold(canonical, "Forwarded") {
			continue
		}
		if _, operatorControlled := h.upstreamHeaders[canonical]; operatorControlled {
			continue
		}
		if risk.IsSensitiveHeader(canonical) && !h.forwardSensitiveHeaders {
			stripped = append(stripped, canonical)
			continue
		}
		for _, value := range values {
			forwarded.Add(canonical, value)
		}
		if risk.IsSensitiveHeader(canonical) {
			inspection[canonical] = "[REDACTED]"
		} else {
			inspection[canonical] = boundedHeaderValues(values)
		}
	}
	for name, values := range h.upstreamHeaders {
		forwarded.Del(name)
		for _, value := range values {
			forwarded.Add(name, value)
		}
	}
	sort.Strings(stripped)
	return forwarded, inspection, stripped
}

func boundedHeaderValues(values []string) any {
	bounded := make([]string, 0, len(values))
	for _, value := range values {
		if len(value) > 1024 {
			value = value[:1024] + "…"
		}
		bounded = append(bounded, value)
	}
	if len(bounded) == 1 {
		return bounded[0]
	}
	return bounded
}

func (h *Handler) forward(response http.ResponseWriter, incoming *http.Request, destination *url.URL, headers http.Header, body []byte, origin string) {
	upstreamRequest, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, destination.String(), bytes.NewReader(body))
	if err != nil {
		h.writeError(response, http.StatusBadGateway, "upstream_request_failed", "Latch could not construct the upstream request.", nil)
		return
	}
	upstreamRequest.Header = headers
	upstreamRequest.Host = h.upstream.Host
	upstreamResponse, err := h.client.Do(upstreamRequest)
	if err != nil {
		fmt.Fprintln(h.diagnostics, "Latch: upstream HTTP API unavailable; request failed closed")
		h.writeError(response, http.StatusBadGateway, "upstream_unavailable", "The upstream API is unavailable.", nil)
		return
	}
	defer upstreamResponse.Body.Close()
	if redirectStatus(upstreamResponse.StatusCode) {
		h.writeError(response, http.StatusBadGateway, "upstream_redirect_forbidden", "Upstream redirects are forbidden by the Latch security boundary.", nil)
		return
	}
	copyResponseHeaders(response.Header(), upstreamResponse.Header)
	if origin != "" {
		setCORS(response, origin)
	}
	response.Header().Set("X-Latch-Decision", string(models.DecisionAllow))
	response.WriteHeader(upstreamResponse.StatusCode)
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
				fmt.Fprintln(h.diagnostics, "Latch: upstream HTTP response stream ended unexpectedly")
			}
			return
		}
	}
}

func (h *Handler) writeDecision(response http.ResponseWriter, result decision.Result) {
	status := http.StatusForbidden
	code := "blocked"
	message := "Latch blocked this API request because it violates security policy."
	if result.Assessment.Decision == models.DecisionRequireApproval {
		status, code = http.StatusPreconditionRequired, "approval_required"
		message = "Latch requires human approval before this API request can be sent."
	}
	switch result.Assessment.DecisionSource {
	case "budget_exhausted":
		status, code, message = http.StatusTooManyRequests, "budget_exhausted", "The agent's cumulative action budget is exhausted."
		for _, budget := range result.Assessment.Budgets {
			if !budget.Exceeded || budget.RetryAfter == "" {
				continue
			}
			if duration, err := time.ParseDuration(budget.RetryAfter); err == nil && duration > 0 {
				seconds := (duration + time.Second - 1) / time.Second
				response.Header().Set("Retry-After", fmt.Sprint(seconds))
				break
			}
		}
	case "audit_failure", "approval_store_failure", "budget_store_failure":
		status, code, message = http.StatusServiceUnavailable, "enforcement_unavailable", "Latch could not verify or record this action safely, so it failed closed."
	}
	h.writeError(response, status, code, message, &result.Assessment)
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Decision *models.Assessment `json:"decision,omitempty"`
}

func (h *Handler) writeError(response http.ResponseWriter, status int, code, message string, assessment *models.Assessment) {
	envelope := errorEnvelope{Decision: assessment}
	envelope.Error.Code, envelope.Error.Message = code, message
	encoded, err := json.Marshal(envelope)
	if err != nil {
		http.Error(response, "Latch adapter error", http.StatusInternalServerError)
		return
	}
	secureErrorHeaders(response)
	response.Header().Set("Content-Type", proxyMediaType)
	response.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func (h *Handler) authorized(values []string) bool {
	if !h.requireToken {
		return true
	}
	if len(values) != 1 {
		return false
	}
	token := strings.TrimSpace(values[0])
	if scheme, value, found := strings.Cut(token, " "); found && strings.EqualFold(scheme, "Bearer") {
		token = strings.TrimSpace(value)
	}
	if token == "" {
		return false
	}
	actual := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(actual[:], h.tokenHash[:]) == 1
}

func (h *Handler) preflight(response http.ResponseWriter, request *http.Request, origin string) {
	if origin == "" {
		h.writeError(response, http.StatusBadRequest, "invalid_preflight", "Browser preflight requires an allowed Origin.", nil)
		return
	}
	method := strings.ToUpper(strings.TrimSpace(request.Header.Get("Access-Control-Request-Method")))
	if method == "" || method == http.MethodConnect || method == http.MethodTrace {
		h.writeError(response, http.StatusBadRequest, "invalid_preflight", "Browser preflight requested an unsupported method.", nil)
		return
	}
	requestedHeaders := request.Header.Get("Access-Control-Request-Headers")
	if len(requestedHeaders) > 16<<10 {
		h.writeError(response, http.StatusRequestHeaderFieldsTooLarge, "invalid_preflight", "Browser preflight requested oversized headers.", nil)
		return
	}
	for _, name := range strings.Split(requestedHeaders, ",") {
		name = strings.TrimSpace(name)
		if name != "" && (!validHeaderName(name) || hopByHop(http.CanonicalHeaderKey(name))) {
			h.writeError(response, http.StatusBadRequest, "invalid_preflight", "Browser preflight requested an unsafe header.", nil)
			return
		}
	}
	response.Header().Set("Access-Control-Allow-Methods", method)
	if requestedHeaders != "" {
		response.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
	}
	response.Header().Set("Access-Control-Max-Age", "600")
	response.WriteHeader(http.StatusNoContent)
}

func isPreflight(request *http.Request) bool {
	return request.Method == http.MethodOptions && strings.TrimSpace(request.Header.Get("Access-Control-Request-Method")) != ""
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

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if !headerTokenCharacter(character) {
			return false
		}
	}
	return true
}

func validateRequestHeaders(headers http.Header) error {
	for name, values := range headers {
		if !validHeaderName(name) {
			return fmt.Errorf("invalid header name")
		}
		for _, value := range values {
			if len(value) > 16<<10 || strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("invalid header value")
			}
		}
	}
	for _, singleton := range []string{"Content-Type", "Content-Encoding"} {
		if len(headers.Values(singleton)) > 1 {
			return fmt.Errorf("duplicate singleton header")
		}
	}
	return nil
}

func headerTokenCharacter(character byte) bool {
	if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))
}

func forbiddenStaticHeader(name, authHeader string) bool {
	if name == authHeader || hopByHop(name) {
		return true
	}
	switch name {
	case "Host", "Content-Length", "Content-Type", "Content-Encoding", "Expect", "Origin", "Forwarded":
		return true
	default:
		return strings.HasPrefix(strings.ToLower(name), "x-forwarded-")
	}
}

func connectionHeaderNames(headers http.Header) map[string]struct{} {
	names := map[string]struct{}{}
	for _, connection := range headers.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			if canonical := http.CanonicalHeaderKey(strings.TrimSpace(name)); canonical != "" {
				names[canonical] = struct{}{}
			}
		}
	}
	return names
}

func copyResponseHeaders(destination, source http.Header) {
	connectionHeaders := connectionHeaderNames(source)
	for name, values := range source {
		canonical := http.CanonicalHeaderKey(name)
		if hopByHop(canonical) {
			continue
		}
		if _, connected := connectionHeaders[canonical]; connected {
			continue
		}
		if strings.HasPrefix(strings.ToLower(canonical), "access-control-") || canonical == "X-Latch-Decision" {
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

func redirectStatus(status int) bool {
	return status >= 300 && status < 400 && status != http.StatusNotModified
}

func setCORS(response http.ResponseWriter, origin string) {
	response.Header().Set("Access-Control-Allow-Origin", origin)
	response.Header().Set("Access-Control-Expose-Headers", "X-Latch-Decision")
	for _, value := range response.Header().Values("Vary") {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), "Origin") {
				return
			}
		}
	}
	response.Header().Add("Vary", "Origin")
}

func secureErrorHeaders(response http.ResponseWriter) {
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

var _ http.Handler = (*Handler)(nil)

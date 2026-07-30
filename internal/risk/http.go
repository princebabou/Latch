package risk

import (
	"encoding/json"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/princebabou/Latch/pkg/models"
)

type destinationKind uint8

var structuredSecretField = regexp.MustCompile(`(?i)(?:^|[{"'&;\s])["']?([a-z0-9_.-]+)["']?\s*[:=]`)

const (
	destinationUnknown destinationKind = iota
	destinationLoopback
	destinationPrivate
	destinationPublic
	destinationMetadata
)

func collectHTTPSignals(action models.Action, collector *signalCollector) {
	collectHTTPArguments(action.Arguments, collector)
	for _, container := range []string{"request", "http_request", "options"} {
		if nested, ok := firstValue(action.Arguments, container); ok {
			if arguments, ok := nested.(map[string]any); ok {
				collectHTTPArguments(arguments, collector)
			}
		}
	}
}

func collectHTTPArguments(arguments map[string]any, collector *signalCollector) {
	endpoint := ""
	if rawEndpoint, found := firstValue(arguments, "url", "endpoint", "uri", "request_url", "base_url"); found {
		var valid bool
		endpoint, valid = rawEndpoint.(string)
		if !valid {
			collector.add("http-parse-ambiguity", 40, "HTTP destination is not a text URL")
			return
		}
	}
	if endpoint == "" {
		if rawHost, found := firstValue(arguments, "host", "hostname"); found {
			host, valid := rawHost.(string)
			if !valid {
				collector.add("http-parse-ambiguity", 40, "HTTP host is not a text value")
				return
			}
			if host != "" {
				endpoint = "https://" + host
			}
		}
	}
	if endpoint == "" {
		return
	}

	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" || parsed.Scheme == "" {
		collector.add("http-parse-ambiguity", 40, "HTTP destination is malformed or lacks an explicit scheme")
		return
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		collector.add("non-http-url-scheme", 60, "Network tool received a non-HTTP URL scheme")
		return
	}

	destination := classifyDestination(parsed.Hostname())
	switch destination {
	case destinationMetadata:
		collector.add("cloud-metadata-access", 90, "Cloud instance metadata endpoint access detected")
	case destinationPrivate:
		collector.add("internal-network-access", 35, "Request targets a private or link-local network address")
	case destinationPublic:
		collector.add("outbound-network", 15, "Outbound public network request detected")
	}

	urlContainsSecret := parsed.User != nil
	for key := range parsed.Query() {
		if sensitiveName(key) {
			urlContainsSecret = true
			break
		}
	}
	if urlContainsSecret {
		collector.add("secret-in-url", 70, "Credentials or secret-bearing parameters are embedded in the URL")
	}

	method := strings.ToUpper(strings.TrimSpace(firstString(arguments, "method", "http_method")))
	switch method {
	case "DELETE":
		collector.add("destructive-http-request", 55, "HTTP DELETE request detected")
	case "PATCH", "PUT":
		collector.add("state-changing-http-request", 25, "State-changing HTTP request detected")
	}

	hasCredentials := containsSensitiveHeaders(arguments)
	hasSensitivePayload := containsSensitivePayload(arguments)
	if hasCredentials && destination != destinationLoopback {
		if destination == destinationPublic || destination == destinationUnknown {
			collector.add("credential-exfiltration", 85, "Credentials are being sent to an external destination")
		} else {
			collector.add("credential-forwarding", 60, "Credentials are being sent across a network boundary")
		}
	}
	if hasSensitivePayload && destination != destinationLoopback {
		if destination == destinationPublic || destination == destinationUnknown {
			collector.add("sensitive-data-exfiltration", 80, "Secret-bearing payload fields are being sent externally")
		} else {
			collector.add("sensitive-data-transfer", 55, "Secret-bearing payload fields are being sent across a network boundary")
		}
	}
	if scheme == "http" && destination != destinationLoopback && (hasCredentials || hasSensitivePayload || urlContainsSecret) {
		collector.add("cleartext-secret-transport", 80, "Secret-bearing request uses unencrypted HTTP")
	}
	tlsVerificationDisabled := boolArgument(arguments, "insecure") || falseArgument(arguments, "verify", "verify_tls", "tls_verify")
	if tlsVerificationDisabled {
		collector.add("tls-verification-disabled", 45, "TLS certificate verification is disabled")
		if hasCredentials || hasSensitivePayload || urlContainsSecret {
			collector.add("insecure-secret-transport", 80, "Secret-bearing request disables TLS certificate verification")
		}
	}
}

func classifyDestination(host string) destinationKind {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return destinationUnknown
	}
	switch host {
	case "metadata.google.internal", "metadata.goog", "instance-data", "metadata.azure.internal":
		return destinationMetadata
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return destinationLoopback
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		ip = parseNumericIPv4(host)
	}
	if ip == nil {
		return destinationPublic
	}
	if isMetadataIP(ip) {
		return destinationMetadata
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return destinationLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return destinationPrivate
	}
	return destinationPublic
}

func parseNumericIPv4(host string) net.IP {
	base := 10
	valueText := host
	if strings.HasPrefix(host, "0x") {
		base = 16
		valueText = host[2:]
	}
	value, err := strconv.ParseUint(valueText, base, 32)
	if err != nil {
		return nil
	}
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func isMetadataIP(ip net.IP) bool {
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.Equal(net.IPv4(169, 254, 169, 254)) ||
			ipv4.Equal(net.IPv4(169, 254, 170, 2)) ||
			ipv4.Equal(net.IPv4(100, 100, 100, 200))
	}
	return false
}

func containsSensitiveHeaders(arguments map[string]any) bool {
	raw, ok := firstValue(arguments, "headers", "header")
	if !ok {
		return false
	}
	switch headers := raw.(type) {
	case map[string]any:
		for key := range headers {
			if sensitiveHeader(key) {
				return true
			}
		}
	case map[string]string:
		for key := range headers {
			if sensitiveHeader(key) {
				return true
			}
		}
	case []any:
		for _, entry := range headers {
			if text, ok := entry.(string); ok {
				key, _, _ := strings.Cut(text, ":")
				if sensitiveHeader(key) {
					return true
				}
			}
		}
	case []string:
		for _, entry := range headers {
			key, _, _ := strings.Cut(entry, ":")
			if sensitiveHeader(key) {
				return true
			}
		}
	case string:
		for _, line := range strings.Split(headers, "\n") {
			key, _, _ := strings.Cut(line, ":")
			if sensitiveHeader(key) {
				return true
			}
		}
	}
	reflected := reflect.ValueOf(raw)
	if reflected.IsValid() && reflected.Kind() == reflect.Map && reflected.Type().Key().Kind() == reflect.String {
		iterator := reflected.MapRange()
		for iterator.Next() {
			if sensitiveHeader(iterator.Key().String()) {
				return true
			}
		}
	}
	return false
}

func containsSensitivePayload(arguments map[string]any) bool {
	raw, ok := firstValue(arguments, "body", "data", "payload", "json", "form")
	if !ok {
		return false
	}
	return sensitivePayloadValue(raw, 0)
}

func sensitivePayloadValue(value any, depth int) bool {
	if depth > 12 {
		return true
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if sensitiveName(key) || sensitivePayloadValue(nested, depth+1) {
				return true
			}
		}
	case map[string]string:
		for key := range typed {
			if sensitiveName(key) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if sensitivePayloadValue(nested, depth+1) {
				return true
			}
		}
	case []string:
		for _, nested := range typed {
			if sensitivePayloadValue(nested, depth+1) {
				return true
			}
		}
	case string:
		var decoded any
		if json.Valid([]byte(typed)) && json.Unmarshal([]byte(typed), &decoded) == nil {
			return sensitivePayloadValue(decoded, depth+1)
		}
		if form, err := url.ParseQuery(typed); err == nil {
			for key := range form {
				if sensitiveName(key) {
					return true
				}
			}
		}
		for _, match := range structuredSecretField.FindAllStringSubmatch(typed, -1) {
			if len(match) > 1 && sensitiveName(match[1]) {
				return true
			}
		}
	default:
		reflected := reflect.ValueOf(value)
		if !reflected.IsValid() {
			return false
		}
		switch reflected.Kind() {
		case reflect.Map:
			if reflected.Type().Key().Kind() != reflect.String {
				return false
			}
			iterator := reflected.MapRange()
			for iterator.Next() {
				if sensitiveName(iterator.Key().String()) || sensitivePayloadValue(iterator.Value().Interface(), depth+1) {
					return true
				}
			}
		case reflect.Slice, reflect.Array:
			for index := 0; index < reflected.Len(); index++ {
				if sensitivePayloadValue(reflected.Index(index).Interface(), depth+1) {
					return true
				}
			}
		}
	}
	return false
}

func sensitiveHeader(name string) bool {
	normalized := normalizeFieldName(name)
	switch normalized {
	case "authorization", "proxy_authorization", "cookie", "set_cookie", "x_api_key", "api_key", "x_auth_token":
		return true
	default:
		return sensitiveName(normalized)
	}
}

func sensitiveName(name string) bool {
	normalized := normalizeFieldName(name)
	for _, fragment := range []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"authorization", "credential", "private_key", "access_key",
		"session_key", "client_secret", "refresh_token",
	} {
		if normalized == fragment || strings.HasSuffix(normalized, "_"+fragment) || strings.HasPrefix(normalized, fragment+"_") {
			return true
		}
	}
	return false
}

func normalizeFieldName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	replacer := strings.NewReplacer("-", "_", ".", "_", " ", "_", "[", "_", "]", "")
	return strings.Trim(replacer.Replace(name), "_")
}

func boolArgument(arguments map[string]any, keys ...string) bool {
	value, ok := firstValue(arguments, keys...)
	if !ok {
		return false
	}
	boolean, _ := value.(bool)
	return boolean
}

func falseArgument(arguments map[string]any, keys ...string) bool {
	value, ok := firstValue(arguments, keys...)
	if !ok {
		return false
	}
	boolean, valid := value.(bool)
	return valid && !boolean
}

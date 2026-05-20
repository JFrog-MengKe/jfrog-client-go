package httpclient

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	// RedirectForwardHeaderEnv enables re-applying client headers (especially authentication) on HTTP
	// redirects when the redirect target host matches RedirectAuthAllowedHostsEnv.
	RedirectForwardHeaderEnv = "JFROG_CLI_REDIRECT_FORWARD_HEADER"
	// RedirectAuthAllowedHostsEnv is a comma-separated allowlist of redirect target hosts.
	// Supports exact hosts (soleng.jfrog.io) and wildcard subdomains (*.jfrog.io).
	RedirectAuthAllowedHostsEnv = "JFROG_CLI_REDIRECT_AUTH_ALLOWED_HOSTS"
	redirectMaxHops             = 10
)

var (
	redirectPolicyOnce sync.Once
	redirectPolicy     struct {
		forwardEnabled bool
		allowedHosts   []string
	}
)

func resetRedirectPolicyForTests() {
	redirectPolicyOnce = sync.Once{}
	redirectPolicy.forwardEnabled = false
	redirectPolicy.allowedHosts = nil
}

func loadRedirectPolicyFromEnv() {
	redirectPolicy.forwardEnabled = strings.EqualFold(strings.TrimSpace(os.Getenv(RedirectForwardHeaderEnv)), "true")
	redirectPolicy.allowedHosts = parseAllowedHosts(os.Getenv(RedirectAuthAllowedHostsEnv))
}

func redirectForwardHeaderEnabled() bool {
	redirectPolicyOnce.Do(loadRedirectPolicyFromEnv)
	return redirectPolicy.forwardEnabled && len(redirectPolicy.allowedHosts) > 0
}

// RedirectForwardHeaderEnabled reports whether redirect auth/header forwarding is enabled
// (JFROG_CLI_REDIRECT_FORWARD_HEADER=true and JFROG_CLI_REDIRECT_AUTH_ALLOWED_HOSTS is non-empty).
func RedirectForwardHeaderEnabled() bool {
	return redirectForwardHeaderEnabled()
}

func redirectAllowedHosts() []string {
	redirectPolicyOnce.Do(loadRedirectPolicyFromEnv)
	return redirectPolicy.allowedHosts
}

// parseAllowedHosts splits a comma-separated host list (whitespace around entries is trimmed).
func parseAllowedHosts(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var hosts []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			hosts = append(hosts, p)
		}
	}
	return hosts
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

// isHostInAllowlist reports whether host matches any allowlist entry.
// Patterns:
//   - exact: soleng.jfrog.io
//   - wildcard subdomain: *.jfrog.io matches foo.jfrog.io but not jfrog.io
func isHostInAllowlist(host string, patterns []string) bool {
	host = normalizeHost(host)
	if host == "" || len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			baseDomain := strings.TrimPrefix(pattern, "*.")
			if host == baseDomain {
				continue
			}
			if strings.HasSuffix(host, "."+baseDomain) {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}

func hostFromRedirectURL(redirectURL string) string {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func allowlistCheckRedirect(httpClientsDetails httputils.HttpClientDetails) func(*http.Request, []*http.Request) error {
	allowed := redirectAllowedHosts()
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= redirectMaxHops {
			return fmt.Errorf("stopped after %d redirects", redirectMaxHops)
		}
		host := req.URL.Hostname()
		if isHostInAllowlist(host, allowed) {
			log.Debug("JFrog CLI redirect policy: forwarding client headers (including auth) to allowlisted host:", host)
			setAuthentication(req, httpClientsDetails)
			copyHeaders(httpClientsDetails, req)
			addUserAgentHeader(req)
			addUberTraceIdHeaderIfSet(req)
		} else {
			log.Debug("JFrog CLI redirect policy: host not in allowlist, using standard HTTP redirect header rules:", host)
		}
		return nil
	}
}

func httpClientsDetailsWithoutCredentials(details httputils.HttpClientDetails) httputils.HttpClientDetails {
	out := details
	out.User = ""
	out.Password = ""
	out.ApiKey = ""
	out.AccessToken = ""
	if out.Headers != nil {
		headers := make(map[string]string, len(out.Headers))
		for k, v := range out.Headers {
			if isAuthRelatedHeader(k) {
				continue
			}
			headers[k] = v
		}
		out.Headers = headers
	}
	return out
}

func isAuthRelatedHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "x-jfrog-art-api", "x-jfrog-api-key":
		return true
	default:
		return false
	}
}

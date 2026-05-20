package httpclient

import (
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/stretchr/testify/assert"
)

func TestParseAllowedHosts(t *testing.T) {
	assert.Nil(t, parseAllowedHosts(""))
	assert.Equal(t, []string{"soleng.jfrog.io", "*.jfrog.io"}, parseAllowedHosts(" soleng.jfrog.io , *.jfrog.io "))
}

func TestIsHostInAllowlist(t *testing.T) {
	patterns := []string{"soleng.jfrog.io", "*.jfrog.io"}

	assert.True(t, isHostInAllowlist("soleng.jfrog.io", patterns))
	assert.True(t, isHostInAllowlist("SOLENG.JFROG.IO", patterns))
	assert.True(t, isHostInAllowlist("catalog.jfrog.io", patterns))
	assert.True(t, isHostInAllowlist("a.b.jfrog.io", patterns))

	assert.False(t, isHostInAllowlist("jfrog.io", patterns))
	assert.False(t, isHostInAllowlist("evil.example.com", patterns))
	assert.False(t, isHostInAllowlist("", patterns))
}

func TestIsHostInAllowlistWildcardOnly(t *testing.T) {
	patterns := []string{"*.jfrog.io"}
	assert.True(t, isHostInAllowlist("soleng.jfrog.io", patterns))
	assert.False(t, isHostInAllowlist("jfrog.io", patterns))
}

func TestIsHostInAllowlistWithPort(t *testing.T) {
	patterns := []string{"soleng.jfrog.io"}
	assert.True(t, isHostInAllowlist("soleng.jfrog.io:443", patterns))
}

func TestRedirectForwardHeaderEnabled(t *testing.T) {
	t.Setenv(RedirectForwardHeaderEnv, "true")
	t.Setenv(RedirectAuthAllowedHostsEnv, "soleng.jfrog.io")
	resetRedirectPolicyForTests()
	assert.True(t, redirectForwardHeaderEnabled())

	t.Setenv(RedirectForwardHeaderEnv, "false")
	resetRedirectPolicyForTests()
	assert.False(t, redirectForwardHeaderEnabled())

	t.Setenv(RedirectForwardHeaderEnv, "true")
	t.Setenv(RedirectAuthAllowedHostsEnv, "")
	resetRedirectPolicyForTests()
	assert.False(t, redirectForwardHeaderEnabled())
}

func TestHttpClientsDetailsWithoutCredentials(t *testing.T) {
	details := httputils.HttpClientDetails{
		User:        "u",
		Password:    "p",
		AccessToken: "tok",
		Headers: map[string]string{
			"Authorization":   "Bearer x",
			"X-JFrog-Art-Api": "key",
			"X-Custom":        "keep",
		},
	}
	out := httpClientsDetailsWithoutCredentials(details)
	assert.Empty(t, out.User)
	assert.Empty(t, out.Password)
	assert.Empty(t, out.AccessToken)
	assert.Equal(t, "keep", out.Headers["X-Custom"])
	assert.NotContains(t, out.Headers, "Authorization")
	assert.NotContains(t, out.Headers, "X-JFrog-Art-Api")
}

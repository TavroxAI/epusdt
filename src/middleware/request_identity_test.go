package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

// extractorFor builds the configured extractor and asks it for the client address
// of a request with the given peer and headers.
func extractorFor(t *testing.T, trustedProxies, remoteAddr string, headers map[string]string) string {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)
	if trustedProxies != "" {
		viper.Set("trusted_proxies", trustedProxies)
	}

	e := echo.New()
	ConfigureIPExtractor(e)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return e.NewContext(req, httptest.NewRecorder()).RealIP()
}

// realIPFor mirrors the nginx config used in production: both headers set to the
// address the proxy saw, the peer being the proxy.
func realIPFor(t *testing.T, trustedProxies string) string {
	t.Helper()
	return extractorFor(t, trustedProxies, "192.0.2.1:1234", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 192.0.2.55",
		"X-Real-IP":       "203.0.113.9",
	})
}

// TestConfigureIPExtractorIgnoresForwardedHeaderFromPublicPeer covers vuln-0008:
// an internet client must not be able to choose the address it is judged by.
func TestConfigureIPExtractorIgnoresForwardedHeaderFromPublicPeer(t *testing.T) {
	if got := realIPFor(t, ""); got != "192.0.2.1" {
		t.Fatalf("RealIP = %q, want the direct peer 192.0.2.1", got)
	}
}

// TestConfigureIPExtractorHonoursConfiguredProxy is the counter-case: a declared
// proxy's header is believed, and the address is the nearest untrusted hop rather
// than whatever the client put first.
func TestConfigureIPExtractorHonoursConfiguredProxy(t *testing.T) {
	// The /24 trusts both hops the proxy chain added, so the untrusted client
	// address is the one furthest left.
	if got := realIPFor(t, "192.0.2.0/24"); got != "203.0.113.9" {
		t.Fatalf("RealIP = %q, want 203.0.113.9", got)
	}
	// A bare IP trusts only the direct peer, so the address stays at the hop that
	// peer reported.
	if got := realIPFor(t, "192.0.2.1"); got != "192.0.2.55" {
		t.Fatalf("RealIP with a bare IP proxy = %q, want 192.0.2.55", got)
	}
}

// TestConfigureIPExtractorIgnoresClientPrependedHops pins the spoofing case: with a
// trusted proxy configured, a value the client prepends to X-Forwarded-For is not
// the address used.
func TestConfigureIPExtractorIgnoresClientPrependedHops(t *testing.T) {
	got := extractorFor(t, "192.0.2.0/24", "192.0.2.1:1234", map[string]string{
		// The client prepends a fake hop; the proxy appends the real address.
		"X-Forwarded-For": "1.2.3.4, 198.51.100.7",
	})
	if got != "198.51.100.7" {
		t.Fatalf("RealIP = %q, want the hop appended by the proxy", got)
	}
}

// TestLocalProxyOverwritingXFFIsHonoured is the production shape: nginx on the same
// host sets X-Forwarded-For to $remote_addr (overwrite, not append). No
// trusted_proxies entry is needed because the peer is loopback.
func TestLocalProxyOverwritingXFFIsHonoured(t *testing.T) {
	got := extractorFor(t, "", "127.0.0.1:54321", map[string]string{
		"X-Forwarded-For": "198.51.100.7",
		"X-Real-IP":       "198.51.100.7",
	})
	if got != "198.51.100.7" {
		t.Fatalf("RealIP = %q, want the client address from the local proxy", got)
	}
}

// TestXRealIPOnlyProxyIsHonoured keeps the old Echo default's behaviour for proxies
// that send only X-Real-IP, and only when the peer is trusted.
func TestXRealIPOnlyProxyIsHonoured(t *testing.T) {
	trusted := extractorFor(t, "", "127.0.0.1:54321", map[string]string{
		"X-Real-IP": "198.51.100.7",
	})
	if trusted != "198.51.100.7" {
		t.Fatalf("RealIP from a local proxy = %q, want 198.51.100.7", trusted)
	}

	untrusted := extractorFor(t, "", "192.0.2.1:1234", map[string]string{
		"X-Real-IP": "198.51.100.7",
	})
	if untrusted != "192.0.2.1" {
		t.Fatalf("RealIP from a public peer = %q, want the peer address", untrusted)
	}
}

// TestXForwardedForWinsOverXRealIP keeps a single, predictable source.
func TestXForwardedForWinsOverXRealIP(t *testing.T) {
	got := extractorFor(t, "", "127.0.0.1:54321", map[string]string{
		"X-Forwarded-For": "198.51.100.7",
		"X-Real-IP":       "203.0.113.9",
	})
	if got != "198.51.100.7" {
		t.Fatalf("RealIP = %q, want the X-Forwarded-For value", got)
	}
}

// TestUnparsableForwardedChainFallsBackToPeer stops a malformed header from being
// treated as an address.
func TestUnparsableForwardedChainFallsBackToPeer(t *testing.T) {
	got := extractorFor(t, "", "127.0.0.1:54321", map[string]string{
		"X-Forwarded-For": "not-an-ip",
	})
	if got != "127.0.0.1" {
		t.Fatalf("RealIP = %q, want the direct peer", got)
	}
}

func TestParseProxyEntry(t *testing.T) {
	cases := map[string]bool{
		"192.0.2.1":      true,
		"192.0.2.0/24":   true,
		"::1":            true,
		"10.0.0.0/8":     true,
		"":               false,
		"not-an-address": false,
		"192.0.2.0/999":  false,
	}
	for entry, want := range cases {
		if got := parseProxyEntry(entry) != nil; got != want {
			t.Errorf("parseProxyEntry(%q) valid = %v, want %v", entry, got, want)
		}
	}
}

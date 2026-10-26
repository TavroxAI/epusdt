package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestValidatePublicHTTPURLRejectsNonPublicRanges covers vuln-0013: the classifier
// used net.IP's built-in predicates only, which let RFC 6598 shared address space
// (including the Alibaba Cloud metadata address), the IETF protocol block, the
// benchmark range and IPv6 unique-local through.
func TestValidatePublicHTTPURLRejectsNonPublicRanges(t *testing.T) {
	blocked := []string{
		"http://100.64.0.1/notify",
		"http://100.100.100.200/latest/meta-data/",
		"http://192.0.0.8/notify",
		"http://192.0.2.10/notify",
		"http://198.18.0.1/notify",
		"http://198.19.255.255/notify",
		"http://203.0.113.9/notify",
		"http://240.0.0.1/notify",
		"http://[fc00::1]/notify",
		"http://[fe80::1]/notify",
		"http://[2001:db8::1]/notify",
	}
	for _, raw := range blocked {
		t.Run(raw, func(t *testing.T) {
			if err := ValidatePublicHTTPURL(raw); err == nil {
				t.Fatalf("ValidatePublicHTTPURL(%q) returned nil, want a non-public rejection", raw)
			}
		})
	}

	for _, raw := range []string{"https://93.184.216.34/notify", "https://8.8.8.8/notify", "https://[2606:4700:4700::1111]/notify"} {
		if err := ValidatePublicHTTPURL(raw); err != nil {
			t.Errorf("ValidatePublicHTTPURL(%q) = %v, want accepted", raw, err)
		}
	}
}

// TestSafeClientRefusesNonPublicDial covers vuln-0012's dial-time half: even when
// the URL was validated earlier, connecting to a non-public address is refused.
func TestSafeClientRefusesNonPublicDial(t *testing.T) {
	AllowNonPublicForTest(false)
	t.Cleanup(func() { AllowNonPublicForTest(false) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewSafeHTTPClient(2 * time.Second)
	if _, err := client.Get(server.URL); err == nil {
		t.Fatal("safe client connected to a loopback address")
	} else if !strings.Contains(err.Error(), "non-public address") {
		t.Fatalf("error = %v, want a non-public address refusal", err)
	}
}

// TestSafeClientRefusesRedirectToNonPublicTarget covers the redirect half: a
// public host that answers 302 must not turn the callback into an internal
// request.
func TestSafeClientRefusesRedirectToNonPublicTarget(t *testing.T) {
	// The redirect target is validated by URL, so the dial relaxation used to
	// reach the test server does not weaken this assertion.
	AllowNonPublicForTest(true)
	t.Cleanup(func() { AllowNonPublicForTest(false) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.10.10.10/internal", http.StatusFound)
	}))
	defer server.Close()

	client := NewSafeHTTPClient(2 * time.Second)
	if _, err := client.Get(server.URL); err == nil {
		t.Fatal("safe client followed a redirect into a private address")
	}
}

// TestSafeRedirectPolicyCapsChain bounds a redirect loop. The hop chain is built
// directly because every hop of a local test server is loopback, which the URL
// guard refuses before the cap could ever apply.
func TestSafeRedirectPolicyCapsChain(t *testing.T) {
	via := make([]*http.Request, maxCallbackRedirects)
	for i := range via {
		via[i] = httptest.NewRequest(http.MethodGet, "https://93.184.216.34/", nil)
	}

	// An IP literal keeps the check DNS-free, so the assertion is about the policy
	// and not about the resolver in the test environment.
	req := httptest.NewRequest(http.MethodGet, "https://93.184.216.34/next", nil)
	err := redirectPolicy(maxCallbackRedirects)(req, via)
	if err == nil {
		t.Fatal("redirect policy allowed a chain at the limit")
	}
	if !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("error = %v, want a redirect limit error", err)
	}

	// One hop short of the limit, a public target is allowed and a private one is
	// still refused.
	shortChain := via[:maxCallbackRedirects-1]
	if err := redirectPolicy(maxCallbackRedirects)(req, shortChain); err != nil {
		t.Fatalf("public redirect target rejected: %v", err)
	}
	privateReq := httptest.NewRequest(http.MethodGet, "http://10.0.0.5/internal", nil)
	if err := redirectPolicy(maxCallbackRedirects)(privateReq, shortChain); err == nil {
		t.Fatal("redirect policy accepted a private redirect target")
	}
}

package security

import (
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"
)

// allowNonPublicDestinations relaxes the outbound address policy. Only tests set
// it: they deliver callbacks to httptest servers listening on loopback, which the
// production policy must refuse.
var allowNonPublicDestinations atomic.Bool

// AllowNonPublicForTest relaxes NewSafeHTTPClient's address policy. Test-only.
func AllowNonPublicForTest(enabled bool) {
	allowNonPublicDestinations.Store(enabled)
}

// maxCallbackRedirects bounds a callback redirect chain.
const maxCallbackRedirects = 5

// NewSafeHTTPClient returns an HTTP client for destinations an attacker can
// choose (merchant callback URLs).
//
// Two independent controls sit at the points where the request is actually made,
// rather than only where the URL was validated:
//
//   - a dial-time check on the resolved socket address, so a host that passed the
//     create-time check and later resolves to loopback / RFC1918 / metadata space
//     (DNS rebinding) cannot be connected to;
//   - a redirect policy that re-validates every hop, so a public host answering
//     302 cannot turn the callback into a request to the internal network.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   controlNonPublic,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: redirectPolicy(maxCallbackRedirects),
	}
}

// redirectPolicy re-validates every hop and bounds the chain. The check runs
// against the redirect target before it is dialled, so a public host answering
// 302 cannot redirect the callback into the internal network.
func redirectPolicy(maxHops int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxHops {
			return fmt.Errorf("stopped after %d redirects", maxHops)
		}
		return ValidatePublicHTTPURL(req.URL.String())
	}
}

// controlNonPublic runs after the connection target has been resolved and before
// it is dialled, which is the last point where a rebinding host can be caught.
func controlNonPublic(_, address string, _ syscall.RawConn) error {
	if allowNonPublicDestinations.Load() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("refuse outbound dial: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("refuse outbound dial: %q is not an IP address", host)
	}
	if isUnsafeIP(ip) {
		return fmt.Errorf("refuse outbound dial to non-public address %s", ip)
	}
	return nil
}

package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/GMWalletApp/epusdt/config"
	"github.com/labstack/echo/v4"
)

// ConfigureIPExtractor makes ctx.RealIP() return an address the caller cannot
// forge, so per-key IP allow-lists and login throttling cannot be bypassed with a
// request header.
//
// Echo's zero value reads X-Forwarded-For / X-Real-IP from any peer, which means
// a merchant can choose the address its API key is judged by. Configuring an
// extractor moves that decision to the connection:
//
//   - no trusted_proxies configured: forwarding headers are honoured only when
//     the direct peer is loopback, link-local or private, i.e. a local reverse
//     proxy. A public peer's header is ignored, so the value cannot be chosen by
//     the caller.
//   - trusted_proxies configured: only those peers have their headers believed,
//     and every other default (loopback/private) is switched off so the list is
//     the complete policy.
func ConfigureIPExtractor(e *echo.Echo) {
	proxies := config.TrustedProxies()
	if len(proxies) == 0 {
		e.IPExtractor = newClientIPExtractor(ipTrust{
			loopback:   true,
			linkLocal:  true,
			privateNet: true,
		})
		return
	}

	trust := ipTrust{}
	for _, entry := range proxies {
		if ipnet := parseProxyEntry(entry); ipnet != nil {
			trust.ranges = append(trust.ranges, ipnet)
		}
	}
	e.IPExtractor = newClientIPExtractor(trust)
}

// ipTrust is the set of peers whose forwarding headers are believed.
type ipTrust struct {
	loopback   bool
	linkLocal  bool
	privateNet bool
	ranges     []*net.IPNet
}

func (t ipTrust) trusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if t.loopback && ip.IsLoopback() {
		return true
	}
	if t.linkLocal && ip.IsLinkLocalUnicast() {
		return true
	}
	if t.privateNet && ip.IsPrivate() {
		return true
	}
	candidate := ip
	if ip4 := ip.To4(); ip4 != nil {
		candidate = ip4
	}
	for _, ipnet := range t.ranges {
		if ipnet.Contains(candidate) {
			return true
		}
	}
	return false
}

// newClientIPExtractor resolves the client address from the connection plus the
// forwarding headers, and only from the headers when the direct peer is trusted.
//
// X-Forwarded-For is walked right-to-left including the direct peer itself: the
// right-most untrusted hop is the client, so a public peer's own address wins
// immediately (nothing in the header can change it) and a trusted proxy's entries
// are skipped. A client-supplied prefix is therefore never the answer. X-Real-IP
// is the fallback for proxies that send only that header (nginx's `proxy_set_header
// X-Real-IP $remote_addr`), which the previous Echo default also honoured.
func newClientIPExtractor(trust ipTrust) echo.IPExtractor {
	return func(req *http.Request) string {
		direct := directPeerIP(req)

		if xffValues := req.Header.Values("X-Forwarded-For"); len(xffValues) > 0 {
			// The peer is the last hop, exactly like the wire path: a proxy
			// appends what it saw, so the peer decides where the chain stops.
			hops := append(strings.Split(strings.Join(xffValues, ","), ","), direct)
			for i := len(hops) - 1; i >= 0; i-- {
				hop := strings.TrimSpace(hops[i])
				if hop == "" {
					continue
				}
				ip := net.ParseIP(hop)
				if ip == nil {
					// An unparsable chain cannot be trusted end to end.
					return direct
				}
				if !trust.trusted(ip) {
					return ip.String()
				}
			}
			// Every hop is trusted (e.g. a chain of proxies inside one private
			// network): the left-most entry is the furthest we can see.
			for _, hop := range hops {
				if hop = strings.TrimSpace(hop); hop != "" {
					return hop
				}
			}
			return direct
		}

		if realIP := strings.TrimSpace(req.Header.Get("X-Real-IP")); realIP != "" {
			if ip := net.ParseIP(realIP); ip != nil && trust.trusted(net.ParseIP(direct)) {
				return ip.String()
			}
		}
		return direct
	}
}

// directPeerIP returns the address of the TCP peer, without the port.
func directPeerIP(req *http.Request) string {
	if req == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// parseProxyEntry accepts a bare IP or a CIDR block; anything else is ignored
// rather than silently widening the trusted set.
func parseProxyEntry(entry string) *net.IPNet {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}
	if strings.Contains(entry, "/") {
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil
		}
		return ipnet
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil
	}
	bits := 128
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		bits = 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

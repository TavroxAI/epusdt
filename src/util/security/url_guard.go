package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const dnsLookupTimeout = 3 * time.Second

var lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// ValidatePublicHTTPURL verifies that raw is an HTTP(S) URL whose host does not
// point to localhost, private networks, link-local addresses, or metadata IPs.
func ValidatePublicHTTPURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("url is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("url scheme must be http or https")
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return errors.New("url host is required")
	}
	if strings.Contains(host, "%") {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	if strings.TrimSuffix(strings.ToLower(host), ".") == "localhost" {
		return fmt.Errorf("url host %q is not allowed", host)
	}

	if ip := net.ParseIP(host); ip != nil {
		return validatePublicIP(host, ip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()

	addrs, err := lookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve url host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("resolve url host %q: no addresses", host)
	}
	for _, addr := range addrs {
		if err := validatePublicIP(host, addr.IP); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicIP(host string, ip net.IP) error {
	if isUnsafeIP(ip) {
		return fmt.Errorf("url host %q resolves to disallowed address %s", host, ip.String())
	}
	return nil
}

// nonPublicCIDRs are address ranges that must never be reachable from a
// merchant-controlled URL. net.IP's built-in predicates cover loopback, RFC1918,
// link-local and multicast, but not the rest of the "not the public internet"
// space: the RFC 6598 shared range (which contains the Alibaba Cloud metadata
// address 100.100.100.200), the IETF protocol assignments block, the benchmark
// range, documentation ranges, and unique-local IPv6. They are listed explicitly
// because a classifier that merely checks IsPrivate leaves every one of them open.
var nonPublicCIDRs = func() []*net.IPNet {
	blocks := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::/128",
		"::1/128",
		"64:ff9b:1::/48",
		"100::/64",
		"2001:db8::/32",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	nets := make([]*net.IPNet, 0, len(blocks))
	for _, block := range blocks {
		_, ipnet, err := net.ParseCIDR(block)
		if err != nil {
			panic("invalid non-public CIDR " + block + ": " + err.Error())
		}
		nets = append(nets, ipnet)
	}
	return nets
}()

func isUnsafeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		!ip.IsGlobalUnicast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, ipnet := range nonPublicCIDRs {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

package service

import (
	"net/url"
	"strings"

	"github.com/GMWalletApp/epusdt/util/constant"
)

// validateMerchantRedirectURL accepts an empty redirect target or an absolute
// http/https URL. It is applied where the value enters the system (order
// creation) because the value is merchant-controlled and is handed to
// window.location.href by the cashier: a javascript: target runs in the gateway
// origin, which also serves the admin console, so a merchant could otherwise
// reach operator authority.
func validateMerchantRedirectURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return constant.OrderRedirectURLErr
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return constant.OrderRedirectURLErr
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return constant.OrderRedirectURLErr
	}
	return nil
}

// safeMerchantRedirectURL returns raw only when it passes
// validateMerchantRedirectURL, and the empty string otherwise. It is applied
// where the value is used, so rows written before the input check existed (or by
// any future writer that forgets it) still cannot reach the cashier.
func safeMerchantRedirectURL(raw string) string {
	if validateMerchantRedirectURL(raw) != nil {
		return ""
	}
	return strings.TrimSpace(raw)
}

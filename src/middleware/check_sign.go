package middleware

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/util/constant"
	"github.com/GMWalletApp/epusdt/util/json"
	"github.com/GMWalletApp/epusdt/util/sign"
	"github.com/labstack/echo/v4"
)

// Context keys populated by CheckApiSign after successful verification.
// Handlers (pay/order creation) pull ApiKeyIDKey to stamp order.api_key_id.
const (
	ApiKeyIDKey  = "api_key_id"
	ApiKeyRowKey = "api_key_row"
)

// CheckApiSign validates the request signature against the secret_key of
// the api_keys row matching the submitted "pid" field. A single row is
// valid for all gateway flows — identification is always by pid.
//
// Flow:
//  1. Extract the parameters from the body and the query string.
//  2. Refuse a field that arrives through both, because the handler cannot tell
//     which one the merchant signed (see mergeRequestParams).
//  3. Look up the enabled row by pid; if missing, return signature error.
//  4. Verify signature == lowercase hex HMAC-SHA256(sorted_params, secret_key),
//     over the same merged parameter set the handler binds.
//  5. Enforce IP whitelist (empty = allow any).
//  6. Bump call_count / last_used_at (best-effort).
//  7. Stash api_key_id + row in context and rewind the body.
func CheckApiSign() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			params, err := io.ReadAll(ctx.Request().Body)
			if err != nil {
				return constant.SignatureErr
			}
			// Rewind the body for downstream bindings regardless of outcome.
			ctx.Request().Body = io.NopCloser(bytes.NewBuffer(params))

			m := make(map[string]interface{})
			contentType := ctx.Request().Header.Get("Content-Type")
			if strings.Contains(contentType, "application/x-www-form-urlencoded") {
				values, parseErr := url.ParseQuery(string(params))
				if parseErr != nil {
					return constant.SignatureErr
				}
				for k, vs := range values {
					if len(vs) > 0 {
						m[k] = vs[0]
					}
				}
			} else {
				if err = json.Cjson.Unmarshal(params, &m); err != nil {
					return constant.SignatureErr
				}
			}
			if err = mergeRequestParams(m, ctx); err != nil {
				return constant.SignatureErr
			}
			signature, ok := m["signature"]
			if !ok {
				return constant.SignatureErr
			}
			identifier := extractPid(m)
			if identifier == "" {
				return constant.SignatureErr
			}

			row, err := data.GetEnabledApiKey(identifier)
			if err != nil || row.ID == 0 {
				return constant.SignatureErr
			}

			checkSignature, err := sign.GetHMACSHA256(m, row.SecretKey)
			if err != nil {
				return constant.SignatureErr
			}
			signatureStr, _ := signature.(string)
			if subtle.ConstantTimeCompare([]byte(checkSignature), []byte(signatureStr)) != 1 {
				return constant.SignatureErr
			}

			if !IsIPWhitelisted(row.IpWhitelist, ctx.RealIP()) {
				return constant.SignatureErr
			}

			_ = data.TouchApiKeyUsage(row.ID)

			ctx.Set(ApiKeyIDKey, row.ID)
			ctx.Set(ApiKeyRowKey, row)
			return next(ctx)
		}
	}
}

// mergeRequestParams folds the query string into the parameter set that is
// signed, and refuses a field that appears in both the body and the query.
//
// The handler binds body and query together (Echo merges them for form
// bindings), while the signature used to cover only the body. A request signed
// for amount=100.00 could therefore be replayed with "?amount=0.01" and create an
// order at the attacker's price, and unsigned redirect_url / payment_type / token
// / network values were persisted. Two rules close that:
//
//   - everything the handler can see is inside the signed set, so an added query
//     parameter changes the signature;
//   - a field present in both places is rejected instead of guessed, because
//     "which one wins" depends on spelling and case (AMOUNT in the body vs amount
//     in the query), and only the merchant knows what it meant to sign.
//
// An identical repeat (same key, same value) is harmless and is allowed.
func mergeRequestParams(m map[string]interface{}, ctx echo.Context) error {
	seen := make(map[string]string, len(m))
	for key := range m {
		lower := strings.ToLower(key)
		if existing, ok := seen[lower]; ok && existing != key {
			return fmt.Errorf("parameter %q appears with two spellings", key)
		}
		seen[lower] = key
	}
	query := ctx.QueryParams()
	if len(query) == 0 {
		return nil
	}
	for key, values := range query {
		if len(values) == 0 {
			continue
		}
		lower := strings.ToLower(key)
		if existing, ok := seen[lower]; ok {
			existingValue, isString := m[existing].(string)
			if existing != key || !isString || existingValue != values[0] {
				return fmt.Errorf("parameter %q is present in both body and query", key)
			}
			continue
		}
		seen[lower] = key
		m[key] = values[0]
	}
	return nil
}

// extractPid reads the "pid" field from the request body. JSON numbers// unmarshal to float64 (EPAY merchants typically send numeric pid); we
// format with -1 precision to drop trailing zeros so "1000" matches
// regardless of whether the client sent a string or a number.
func extractPid(m map[string]interface{}) string {
	v, ok := m["pid"]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

// IsIPWhitelisted checks the CSV IP list. Empty list = open.
// Entries may be single IPs or CIDR blocks.
func IsIPWhitelisted(csv, remote string) bool {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return true
	}
	remoteIP := net.ParseIP(remote)
	for _, raw := range strings.Split(csv, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && remoteIP != nil && cidr.Contains(remoteIP) {
				return true
			}
			continue
		}
		if entry == remote {
			return true
		}
	}
	return false
}

package middleware

import (
	"crypto/hmac"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/GMWalletApp/epusdt/config"
	"github.com/GMWalletApp/epusdt/util/constant"
	"github.com/GMWalletApp/epusdt/util/log"
	"github.com/GMWalletApp/epusdt/util/sign"
	"github.com/labstack/echo/v4"
)

// reconcileTimestampSkewSeconds bounds how far the merchant's "ts" may drift
// from this server's clock. A longer window buys nothing: the same three signed
// fields stay replayable for as long as they verify.
const reconcileTimestampSkewSeconds int64 = 300

// CheckReconcileSign authenticates the by-order-id order lookup.
//
// This is deliberately NOT CheckApiSign: that middleware resolves a merchant
// api_keys row from "pid" and verifies with that row's secret_key, while
// reconciliation is authorized by ONE static, instance-wide key from .env
// (gmpay_reconcile_key) that may read any order on this instance.
//
// Flow:
//  1. Load the reconcile key; when it is missing every request is rejected
//     (fail-closed — an unauthenticated order lookup is worse than a 401).
//  2. Read order_id from the path and pid / ts / signature from the query.
//  3. Reject a "ts" that is not Unix seconds within +/-300s of now.
//  4. Verify signature == lowercase hex HMAC-SHA256(canonical
//     order_id/pid/ts, reconcileKey), compared with hmac.Equal so a partial
//     match cannot leak through timing.
//
// pid and ts are audit fields only. The lookup is never scoped by them
// because one instance serves a single tenant, and any failure answered here
// is a signature error (401) so the merchant's five-class classification can
// never mistake an auth failure for "order not found".
func CheckReconcileSign() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			reconcileKey, err := config.GetGMPayReconcileKey()
			if err != nil || strings.TrimSpace(reconcileKey) == "" {
				log.Sugar.Errorf("by-order-id lookup rejected: gmpay reconcile key is unavailable (order_id=%q): %v", ctx.Param("order_id"), err)
				return constant.SignatureErr
			}

			orderID := ctx.Param("order_id")
			pid := ctx.QueryParam("pid")
			rawTimestamp := ctx.QueryParam("ts")
			rawSignature := ctx.QueryParam("signature")

			timestamp, err := strconv.ParseInt(strings.TrimSpace(rawTimestamp), 10, 64)
			if err != nil {
				log.Sugar.Warnf("by-order-id lookup rejected: ts %q is not unix seconds (order_id=%q pid=%q)", rawTimestamp, orderID, pid)
				return constant.SignatureErr
			}
			now := time.Now().Unix()
			if timestamp < now-reconcileTimestampSkewSeconds || timestamp > now+reconcileTimestampSkewSeconds {
				log.Sugar.Warnf("by-order-id lookup rejected: ts %d is outside the %ds window (order_id=%q pid=%q)", timestamp, reconcileTimestampSkewSeconds, orderID, pid)
				return constant.SignatureErr
			}

			expected, err := sign.GetHMACSHA256(map[string]interface{}{
				"order_id": orderID,
				"pid":      pid,
				"ts":       timestamp,
			}, reconcileKey)
			if err != nil {
				return constant.SignatureErr
			}
			expectedBytes, err := hex.DecodeString(expected)
			if err != nil {
				return constant.SignatureErr
			}
			providedBytes, err := hex.DecodeString(strings.TrimSpace(rawSignature))
			if err != nil {
				log.Sugar.Warnf("by-order-id lookup rejected: signature is not hex (order_id=%q pid=%q ts=%d)", orderID, pid, timestamp)
				return constant.SignatureErr
			}
			if !hmac.Equal(providedBytes, expectedBytes) {
				log.Sugar.Warnf("by-order-id lookup rejected: signature mismatch (order_id=%q pid=%q ts=%d)", orderID, pid, timestamp)
				return constant.SignatureErr
			}

			log.Sugar.Debugf("by-order-id lookup authorized (order_id=%q pid=%q ts=%d)", orderID, pid, timestamp)
			return next(ctx)
		}
	}
}

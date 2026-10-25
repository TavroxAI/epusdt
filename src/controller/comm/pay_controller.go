package comm

import (
	"net/http"
	"strings"

	"github.com/GMWalletApp/epusdt/model/request"
	"github.com/GMWalletApp/epusdt/model/response"
	"github.com/GMWalletApp/epusdt/model/service"
	"github.com/GMWalletApp/epusdt/util/constant"
	"github.com/labstack/echo/v4"
)

// CheckoutCounter 收银台
// @Summary      Checkout counter page
// @Description  Return checkout initialization data when the order exists. This endpoint only confirms order existence and returns base order data; call /pay/check-status/{trade_id} for the current order status (1=waiting payment, 2=paid, 3=expired, 4=waiting token/network selection).
// @Description  When status=4, actual_amount is 0 and token/network/receive_address are empty; this state is produced by GMPay placeholders or EPay submit.php when no token/network request values or defaults resolve to a concrete payment asset. The cashier should guide the payer to choose an on-chain token/network or OkPay and then call /pay/switch-network.
// @Description  For EPay orders with a merchant return_url, the response redirect_url is rewritten to the internal /pay/return/{trade_id} hop; the database still stores the merchant's raw return_url.
// @Tags         Payment
// @Produce      json
// @Param        trade_id path string true "Trade ID"
// @Success      200 {object} response.ApiResponse{data=response.CheckoutCounterResponse}
// @Failure      400 {object} response.ApiResponse "Order not found (status_code=10008) or other request error"
// @Router       /pay/checkout-counter-resp/{trade_id} [get]
func (c *BaseCommController) CheckoutCounter(ctx echo.Context) (err error) {
	tradeId := ctx.Param("trade_id")
	resp, err := service.GetCheckoutCounterByTradeId(tradeId)
	if err != nil {
		return c.FailJson(ctx, err)
	}

	return c.SucJson(ctx, resp)
}

// GetOrderByOrderId 按商户单号查询订单签名快照（对账专用）
// @Summary      Get order by order id (signed snapshot)
// @Description  Authenticated, signed order lookup for merchant reconciliation. The request itself is signed with the static instance-level reconcile key (gmpay_reconcile_key): lowercase hex HMAC-SHA256 over the canonical order_id/pid/ts payload, and ts (Unix seconds) must be within 300 seconds of the server clock. pid and ts are audit fields only and never scope the lookup. Any authentication failure is HTTP 401 with status_code=401 so it can never be mistaken for a missing order.
// @Description  The returned snapshot is the checkout-counter body plus order_id, pid, block_transaction_id and an Ed25519 signature over the canonical body (sign_type=ed25519, key_id identifies the signing key). The endpoint sends Cache-Control: no-store.
// @Description  A missing order is 10008; an order whose api_key row is gone is 10045. The two must not be conflated: 10008 may be counted as "order not found", 10045 belongs to pull failures.
// @Tags         Payment
// @Produce      json
// @Param        order_id path string true "Merchant order id (order_id)"
// @Param        pid query string true "API key pid (audit only)"
// @Param        ts query integer true "Unix seconds; must be within 300s of server time"
// @Param        signature query string true "Lowercase hex HMAC-SHA256 of the canonical order_id/pid/ts payload"
// @Success      200 {object} response.ApiResponse{data=response.CheckoutCounterResponse}
// @Failure      400 {object} response.ApiResponse "Stable errno in status_code: 10008 order not found, 10045 order api key unavailable"
// @Failure      401 {object} response.ApiResponse "Reconcile signature rejected (status_code=401)"
// @Router       /payments/gmpay/v1/orders/by-order-id/{order_id} [get]
func (c *BaseCommController) GetOrderByOrderId(ctx echo.Context) error {
	// A signed order snapshot must never be cached by a browser or proxy.
	ctx.Response().Header().Set("Cache-Control", "no-store")
	resp, err := service.GetOrderSnapshotByOrderId(ctx.Param("order_id"))
	if err != nil {
		return c.FailJson(ctx, err)
	}
	return c.SucJson(ctx, resp)
}

// ReturnToMerchant performs the browser-facing EPay success return hop.
// Non-EPay or not-yet-paid orders are sent back to the checkout counter.
// @Summary      Return to merchant (EPAY compat)
// @Description  Browser-facing success return hop for EPay orders. Paid EPay orders are redirected to the merchant return_url with signed legacy EPay query params. Orders that are not EPay or not yet paid are redirected back to the checkout counter.
// @Description  The signed query params reuse the stored request type. On this branch that means either alipay or a supported token.network selector; if the original request omitted type, type=alipay is returned for compatibility.
// @Description  This route also returns explicit business errors when the merchant return_url is missing, the order API key is unavailable, or EPay signature construction fails.
// @Tags         Payment
// @Produce      html
// @Param        trade_id path string true "Trade ID"
// @Success      302 "Redirect to merchant return_url or checkout counter"
// @Failure      400 {object} response.ApiResponse "Stable errno in status_code: 10008 order not found, 10044 invalid order redirect url, 10045 order api key unavailable, 10046 failed to build epay return signature"
// @Router       /pay/return/{trade_id} [get]
func (c *BaseCommController) ReturnToMerchant(ctx echo.Context) error {
	tradeID := ctx.Param("trade_id")
	redirect, err := service.ResolveEPayReturnRedirect(tradeID)
	if err != nil {
		return c.FailJson(ctx, err)
	}
	if redirect.IsMerchantRedirect {
		ctx.Response().Header().Set("Cache-Control", "no-store")
	}
	return ctx.Redirect(http.StatusFound, redirect.TargetURL)
}

// CheckStatus 支付状态检测
// @Summary      Check payment status
// @Description  Return the current order status by trade ID. Status: 1=waiting payment, 2=paid, 3=expired, 4=waiting token/network selection.
// @Tags         Payment
// @Produce      json
// @Param        trade_id path string true "Trade ID"
// @Success      200 {object} response.ApiResponse{data=response.CheckStatusResponse}
// @Failure      400 {object} response.ApiResponse "Order not found (status_code=10008) or other request error"
// @Router       /pay/check-status/{trade_id} [get]
func (c *BaseCommController) CheckStatus(ctx echo.Context) (err error) {
	tradeId := ctx.Param("trade_id")
	order, err := service.GetOrderInfoByTradeId(tradeId)
	if err != nil {
		return c.FailJson(ctx, err)
	}
	resp := response.CheckStatusResponse{
		TradeId: order.TradeId,
		Status:  order.Status,
	}
	return c.SucJson(ctx, resp)
}

// SubmitTxHash 手动提交交易 hash 补单
// @Summary      Submit transaction hash
// @Description  Submit an on-chain transaction hash from the cashier. The hash is verified against the waiting order and, when valid, the same manual payment processing path used by admin mark-paid is executed. Expired orders and OkPay/provider orders are not supported.
// @Description  TON accepts canonical ton:<receive_raw>:<lt>:<hash>, lt:hash, or a unique recent hash-only reference for the order receive address.
// @Description  Aptos accepts a transaction hash.
// @Description  Aptos automatic scanning polls fullnode ledger-version transaction ranges with a runtime cursor.
// @Tags         Payment
// @Accept       json
// @Produce      json
// @Param        trade_id path string true "Trade ID"
// @Param        request body request.ManualPaymentRequest true "Transaction hash payload"
// @Success      200 {object} response.ApiResponse{data=response.ManualPaymentResponse}
// @Failure      400 {object} response.ApiResponse "Stable errno in status_code: 10008 order not found, 10009 invalid params, 10013 not waiting payment, 10038 verification failed, 10039 unsupported provider, 10007 hash already processed"
// @Router       /pay/submit-tx-hash/{trade_id} [post]
func (c *BaseCommController) SubmitTxHash(ctx echo.Context) (err error) {
	tradeId := ctx.Param("trade_id")
	req := new(request.ManualPaymentRequest)
	if err = ctx.Bind(req); err != nil {
		return c.FailJson(ctx, constant.ParamsMarshalErr)
	}
	req.BlockTransactionId = strings.TrimSpace(req.BlockTransactionId)
	if err = c.ValidateStruct(ctx, req); err != nil {
		return c.FailJson(ctx, err)
	}

	resp, err := service.SubmitCashierManualPayment(tradeId, req.BlockTransactionId)
	if err != nil {
		return c.FailJson(ctx, err)
	}
	return c.SucJson(ctx, resp)
}

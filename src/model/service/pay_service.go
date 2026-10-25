package service

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/GMWalletApp/epusdt/config"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/model/response"
	"github.com/GMWalletApp/epusdt/util/constant"
	"github.com/GMWalletApp/epusdt/util/json"
	"github.com/GMWalletApp/epusdt/util/log"
	"github.com/GMWalletApp/epusdt/util/sign"
)

// ErrOrder is returned when checkout initialization cannot find the trade id.
var ErrOrder = constant.OrderNotExists

// GetCheckoutCounterByTradeId returns checkout initialization data for an existing order.
// It does not decide the payment state; callers should use CheckStatus for that.
func GetCheckoutCounterByTradeId(tradeId string) (*response.CheckoutCounterResponse, error) {
	orderInfo, err := data.GetOrderInfoByTradeId(tradeId)
	if err != nil {
		return nil, err
	}
	if orderInfo.ID <= 0 {
		return nil, ErrOrder
	}
	resp := buildCheckoutResponse(orderInfo)
	if orderInfo.PayProvider == mdb.PaymentProviderOkPay {
		providerRow, rowErr := data.GetProviderOrderByTradeIDAndProvider(orderInfo.TradeId, mdb.PaymentProviderOkPay)
		if rowErr != nil {
			return nil, rowErr
		}
		if providerRow.ID > 0 {
			resp.PaymentUrl = providerRow.PayURL
		}
	}
	return resp, nil
}

// gmpaySnapshotSignType is the signature algorithm stamped on the by-order-id
// snapshot. Merchants read it before verifying, so a signing-key rotation shows
// up as a named algorithm change instead of an unexplained mismatch.
const gmpaySnapshotSignType = "ed25519"

// ErrOrderSnapshotSignature reports that a by-order-id snapshot could not be
// verified before it left this process. It is a 5xx on purpose: an unverifiable
// body must read as a server fault, never as a successful lookup, and never as a
// 10008/10045 business answer the merchant would act on.
var ErrOrderSnapshotSignature = &constant.RspError{
	Code: http.StatusInternalServerError,
	Msg:  "order snapshot signature self-check failed",
}

// GetOrderSnapshotByOrderId returns the signed snapshot behind the
// reconciliation lookup (GET /payments/gmpay/v1/orders/by-order-id/{order_id}).
//
// Two failures are deliberately distinct:
//   - the order row is absent -> 10008 (ErrOrder), the not-found contract every
//     other epusdt endpoint uses;
//   - the order exists but its api_key row is gone -> 10045, because the row was
//     found and only its pid is missing. Reporting 10008 here would let a
//     merchant close an order the gateway can still see.
//
// The snapshot is the checkout-counter body augmented with order_id, pid,
// block_transaction_id and the Ed25519 material. Signing lives here, never in
// buildCheckoutResponse: the checkout counter and switch-network must keep
// returning unsigned bodies.
func GetOrderSnapshotByOrderId(orderId string) (*response.CheckoutCounterResponse, error) {
	// The order id is used verbatim: it is the exact string the middleware
	// verified, so a lookup can never see different bytes than the signature.
	orderInfo, err := data.GetOrderInfoByOrderId(orderId)
	if err != nil {
		return nil, err
	}
	if orderInfo.ID <= 0 {
		return nil, ErrOrder
	}

	apiKeyRow, err := data.GetApiKeyByID(orderInfo.ApiKeyID)
	if err != nil {
		return nil, err
	}
	if apiKeyRow.ID == 0 {
		return nil, constant.OrderApiKeyUnavailableErr
	}

	privateKey, err := config.GetGMPaySigningKey()
	if err != nil {
		log.Sugar.Errorf("by-order-id snapshot refused: gmpay signing key is unavailable: %v", err)
		return nil, ErrOrderSnapshotSignature
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrOrderSnapshotSignature
	}

	snapshot := buildCheckoutResponse(orderInfo)
	snapshot.OrderId = orderInfo.OrderId
	snapshot.Pid = apiKeyRow.Pid
	snapshot.BlockTransactionId = orderInfo.BlockTransactionId
	snapshot.SignType = gmpaySnapshotSignType
	snapshot.KeyId = sign.KeyIDFor(publicKey)

	// sign_type and key_id are stamped before signing on purpose: the merchant
	// recomputes the canonical form from the body it received, so every field on
	// the wire except "signature" itself has to be covered.
	signature, err := sign.SignEd25519(*snapshot, privateKey)
	if err != nil {
		log.Sugar.Errorf("by-order-id snapshot signing failed for order %q: %v", orderInfo.OrderId, err)
		return nil, ErrOrderSnapshotSignature
	}
	snapshot.Signature = signature

	if err := verifyOrderSnapshotSignature(snapshot, publicKey); err != nil {
		log.Sugar.Errorf("by-order-id snapshot self-check failed for order %q: %v", orderInfo.OrderId, err)
		return nil, ErrOrderSnapshotSignature
	}
	return snapshot, nil
}

// verifyOrderSnapshotSignature re-canonicalises the serialized snapshot and
// checks it against publicKey. It runs on every response so a body the merchant
// could not verify (for example a future field type the canonicaliser rejects)
// fails closed server-side instead of shipping.
func verifyOrderSnapshotSignature(snapshot *response.CheckoutCounterResponse, publicKey ed25519.PublicKey) error {
	raw, err := json.Cjson.Marshal(snapshot)
	if err != nil {
		return err
	}
	payload := make(map[string]interface{}, 24)
	if err := json.Cjson.Unmarshal(raw, &payload); err != nil {
		return err
	}
	canonical, err := sign.Canonical(payload)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(snapshot.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, []byte(canonical), signature) {
		return errors.New("snapshot signature does not verify")
	}
	return nil
}

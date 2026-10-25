package sign

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/GMWalletApp/epusdt/util/json"
)

// The notify wire format below is shared with the merchant (new-api). The same
// fixture is asserted in its pkg/epusdt/client_test.go, so changing how GMPay
// canonicalises or serialises this payload breaks a test on both sides instead
// of silently breaking interoperability.
const (
	goldenNotifySeed      = "6c1c7d4d6f2a4a3c8f8f1b0f3f9e2a5d4c6b7a8e9f0a1b2c3d4e5f60718293a4"
	goldenNotifyPublicKey = "da11bba1fc4e5a7d6d1637e9b647b302d643bbeff63ba816c1cb2957a0e57dbb"
	goldenNotifyKeyID     = "da11bba1"
	goldenNotifySignature = "184b8885673285a61b8f86f4cb015dcad65b52b94ba8dee1bc82cedd542660afeb3e7191f033b85de5e0721dcdc6b704528e718c1de924ea7ed266f8cad11601"
	goldenNotifyCanonical = "actual_amount=9.99&amount=9.99&block_transaction_id=0xabc123&key_id=da11bba1&order_id=USR42NOABCDEF1713264000&pid=1000&receive_address=TXyz1234567890&sign_type=ed25519&status=2&token=USDT&trade_id=T-20260101-0001"
	goldenNotifyJSON      = `{"actual_amount":9.99,"amount":9.99,"block_transaction_id":"0xabc123","key_id":"da11bba1","order_id":"USR42NOABCDEF1713264000","pid":"1000","receive_address":"TXyz1234567890","sign_type":"ed25519","signature":"184b8885673285a61b8f86f4cb015dcad65b52b94ba8dee1bc82cedd542660afeb3e7191f033b85de5e0721dcdc6b704528e718c1de924ea7ed266f8cad11601","status":2,"token":"USDT","trade_id":"T-20260101-0001"}`
)

func goldenNotifyPayload(t *testing.T) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"pid":                  "1000",
		"trade_id":             "T-20260101-0001",
		"order_id":             "USR42NOABCDEF1713264000",
		"amount":               float64(9.99),
		"actual_amount":        float64(9.99),
		"receive_address":      "TXyz1234567890",
		"token":                "USDT",
		"block_transaction_id": "0xabc123",
		"status":               float64(2),
		"sign_type":            "ed25519",
		"key_id":               goldenNotifyKeyID,
	}
}

func TestGMPayNotifyGoldenVectorIsStable(t *testing.T) {
	priv, err := PrivateKeyFromSeedHex(goldenNotifySeed)
	if err != nil {
		t.Fatalf("derive golden key: %v", err)
	}
	pubHex, err := PublicKeyHex(priv)
	if err != nil {
		t.Fatalf("golden public key: %v", err)
	}
	if pubHex != goldenNotifyPublicKey {
		t.Fatalf("golden public key changed: got %s, want %s", pubHex, goldenNotifyPublicKey)
	}

	payload := goldenNotifyPayload(t)
	canonical, err := Canonical(payload)
	if err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}
	if canonical != goldenNotifyCanonical {
		t.Fatalf("canonical form changed\n got: %s\nwant: %s", canonical, goldenNotifyCanonical)
	}

	signature, err := SignEd25519(payload, priv)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if signature != goldenNotifySignature {
		t.Fatalf("notify signature changed\n got: %s\nwant: %s", signature, goldenNotifySignature)
	}

	payload["signature"] = signature
	encoded, err := json.Cjson.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal golden notify: %v", err)
	}
	if string(encoded) != goldenNotifyJSON {
		t.Fatalf("notify JSON changed\n got: %s\nwant: %s", encoded, goldenNotifyJSON)
	}

	decoded, err := hex.DecodeString(goldenNotifySignature)
	if err != nil {
		t.Fatalf("golden signature is not hex: %v", err)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte(goldenNotifyCanonical), decoded) {
		t.Fatal("golden signature does not verify over the golden canonical form")
	}
}

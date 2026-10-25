package sign

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGetHMACSHA256FixedVector(t *testing.T) {
	params := map[string]interface{}{
		"signature": "ignored",
		"pid":       "1000",
		"empty":     "",
		"nil":       nil,
		"name":      "VIP",
		"amount":    100,
	}

	got, err := GetHMACSHA256(params, "test-secret")
	if err != nil {
		t.Fatalf("GetHMACSHA256() error = %v", err)
	}
	const want = "ced9141fab53a83d1178f903e7c22d8a2a7033520f31e319934e92455a008b6c"
	if got != want {
		t.Fatalf("GetHMACSHA256() = %q, want %q", got, want)
	}
}

func TestGetHMACSHA256StructUsesCanonicalParams(t *testing.T) {
	type payload struct {
		PID       string `json:"pid"`
		Name      string `json:"name"`
		Amount    int    `json:"amount"`
		Signature string `json:"signature"`
	}

	got, err := GetHMACSHA256(payload{
		PID:       "1000",
		Name:      "VIP",
		Amount:    100,
		Signature: "ignored",
	}, "test-secret")
	if err != nil {
		t.Fatalf("GetHMACSHA256() error = %v", err)
	}
	const want = "ced9141fab53a83d1178f903e7c22d8a2a7033520f31e319934e92455a008b6c"
	if got != want {
		t.Fatalf("GetHMACSHA256() = %q, want %q", got, want)
	}
}

func TestGetMD5RemainsUnchanged(t *testing.T) {
	params := map[string]interface{}{
		"signature": "ignored",
		"pid":       "1000",
		"name":      "VIP",
		"amount":    100,
	}

	got, err := Get(params, "test-secret")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	const want = "2203e5d2a13264c188f7fac194a632f8"
	if got != want {
		t.Fatalf("Get() = %q, want %q", got, want)
	}
}

// testPrivateKey keeps fixtures deterministic: the same seed always yields the
// same key pair, so the derived key id can be asserted.
func testPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("epusdt-sign-test-seed"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func TestMapToParamsBoolParticipates(t *testing.T) {
	got, err := MapToParams(map[string]interface{}{
		"is_selected": true,
		"refunded":    false,
		"empty":       "",
		"amount":      float64(100),
	})
	if err != nil {
		t.Fatalf("MapToParams() error = %v", err)
	}
	// false participates (only empty strings are skipped) and the payload stays
	// sorted by the joined "k=v" strings.
	const want = "amount=100&is_selected=true&refunded=false"
	if got != want {
		t.Fatalf("MapToParams() = %q, want %q", got, want)
	}
}

func TestMapToParamsRejectsNestedValues(t *testing.T) {
	for name, value := range map[string]interface{}{
		"nested object": map[string]interface{}{"a": "b"},
		"slice":         []interface{}{"a"},
	} {
		if _, err := MapToParams(map[string]interface{}{"field": value}); err == nil {
			t.Fatalf("%s: expected an error, got none", name)
		}
	}
}

func TestHMACAndEd25519ShareOneCanonicalForm(t *testing.T) {
	payload := map[string]interface{}{
		"order_id": "USR1NOABCDEF1713264000",
		"amount":   float64(9.99),
		"status":   int64(2),
		"token":    "usdt",
	}
	canonical, err := Canonical(payload)
	if err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}

	mac := hmac.New(sha256.New, []byte("reconcile-key-for-test"))
	if _, err := mac.Write([]byte(canonical)); err != nil {
		t.Fatalf("hmac write: %v", err)
	}
	wantHMAC := hex.EncodeToString(mac.Sum(nil))

	gotHMAC, err := GetHMACSHA256(payload, "reconcile-key-for-test")
	if err != nil {
		t.Fatalf("GetHMACSHA256() error = %v", err)
	}
	if gotHMAC != wantHMAC {
		t.Fatalf("HMAC is not computed over Canonical(): got %s, want %s", gotHMAC, wantHMAC)
	}
}

func TestSignEd25519VerifiesAndDetectsTampering(t *testing.T) {
	priv := testPrivateKey(t)
	payload := map[string]interface{}{
		"order_id":    "USR1NOABCDEF1713264000",
		"amount":      float64(9.99),
		"currency":    "usd",
		"status":      int64(2),
		"is_selected": false,
		"sign_type":   "ed25519",
	}
	signature, err := SignEd25519(payload, priv)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	decoded, err := hex.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		t.Fatalf("signature must be hex of %d bytes, got %q (err=%v)", ed25519.SignatureSize, signature, err)
	}

	canonical, err := Canonical(payload)
	if err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte(canonical), decoded) {
		t.Fatal("a freshly produced signature does not verify")
	}

	for _, field := range []string{"amount", "status", "order_id", "is_selected", "sign_type"} {
		tampered := make(map[string]interface{}, len(payload))
		for key, value := range payload {
			tampered[key] = value
		}
		switch field {
		case "amount":
			tampered[field] = float64(0.01)
		case "status":
			tampered[field] = int64(1)
		case "is_selected":
			tampered[field] = true
		case "sign_type":
			tampered[field] = "hmac"
		default:
			tampered[field] = "other-order"
		}
		tamperedCanonical, err := Canonical(tampered)
		if err != nil {
			t.Fatalf("%s: Canonical() error = %v", field, err)
		}
		if ed25519.Verify(pub, []byte(tamperedCanonical), decoded) {
			t.Fatalf("changing %q must invalidate the signature", field)
		}
	}
}

func TestSignEd25519RejectsInvalidKey(t *testing.T) {
	if _, err := SignEd25519(map[string]interface{}{"a": "b"}, ed25519.PrivateKey{1, 2, 3}); err == nil {
		t.Fatal("expected an error for a malformed private key")
	}
}

func TestPrivateKeyFromSeedHex(t *testing.T) {
	priv := testPrivateKey(t)
	pubHex, err := PublicKeyHex(priv)
	if err != nil {
		t.Fatalf("PublicKeyHex() error = %v", err)
	}
	if len(pubHex) != 64 {
		t.Fatalf("public key hex must be 64 characters, got %d", len(pubHex))
	}
	seedHex := hex.EncodeToString(priv.Seed())

	parsed, err := PrivateKeyFromSeedHex("  " + strings.ToUpper(seedHex) + "\n")
	if err != nil {
		t.Fatalf("a valid seed was rejected: %v", err)
	}
	if !parsed.Equal(priv) {
		t.Fatal("parsed key differs from the original")
	}

	for name, raw := range map[string]string{
		"empty":           "",
		"not hex":         strings.Repeat("z", 64),
		"too short":       seedHex[:62],
		"too long":        seedHex + "00",
		"private key hex": hex.EncodeToString(priv),
		"pem":             "-----BEGIN PRIVATE KEY-----",
	} {
		if _, err := PrivateKeyFromSeedHex(raw); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

func TestKeyIDFor(t *testing.T) {
	priv := testPrivateKey(t)
	pubHex, err := PublicKeyHex(priv)
	if err != nil {
		t.Fatalf("PublicKeyHex() error = %v", err)
	}
	id := KeyIDFor(priv.Public().(ed25519.PublicKey))
	if id != strings.ToLower(pubHex)[:8] {
		t.Fatalf("key id must be the first 8 hex characters: got %q, want %q", id, pubHex[:8])
	}
}

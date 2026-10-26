package mq

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GMWalletApp/epusdt/config"
	"github.com/GMWalletApp/epusdt/internal/testutil"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/util/security"
	"github.com/GMWalletApp/epusdt/util/sign"
)

// TestMain relaxes the callback client's address policy: these tests deliver
// callbacks to httptest servers listening on loopback, which production refuses.
func TestMain(m *testing.M) {
	security.AllowNonPublicForTest(true)
	os.Exit(m.Run())
}

func TestProcessExpiredOrdersExpiresWaitingOrdersAndReleasesLocks(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	order := &mdb.Orders{
		TradeId:        "trade_expired",
		OrderId:        "order_expired",
		Amount:         1,
		Currency:       "CNY",
		ActualAmount:   1,
		ReceiveAddress: "wallet_1",
		Token:          "USDT",
		Network:        "tron",
		Status:         mdb.StatusWaitPay,
		NotifyUrl:      "https://merchant.example/callback",
	}
	if err := dao.Mdb.Create(order).Error; err != nil {
		t.Fatalf("create expired order: %v", err)
	}
	if err := dao.Mdb.Model(order).UpdateColumn("created_at", time.Now().Add(-20*time.Minute)).Error; err != nil {
		t.Fatalf("age expired order: %v", err)
	}
	if err := data.LockTransaction("tron", order.ReceiveAddress, order.Token, order.TradeId, order.ActualAmount, time.Hour); err != nil {
		t.Fatalf("lock expired order: %v", err)
	}

	recentOrder := &mdb.Orders{
		TradeId:        "trade_recent",
		OrderId:        "order_recent",
		Amount:         1,
		Currency:       "CNY",
		ActualAmount:   1.01,
		ReceiveAddress: "wallet_1",
		Token:          "USDT",
		Network:        "tron",
		Status:         mdb.StatusWaitPay,
		NotifyUrl:      "https://merchant.example/callback",
	}
	if err := dao.Mdb.Create(recentOrder).Error; err != nil {
		t.Fatalf("create recent order: %v", err)
	}
	if err := data.LockTransaction("tron", recentOrder.ReceiveAddress, recentOrder.Token, recentOrder.TradeId, recentOrder.ActualAmount, time.Hour); err != nil {
		t.Fatalf("lock recent order: %v", err)
	}

	placeholder := &mdb.Orders{
		TradeId:   "trade_wait_select_expired",
		OrderId:   "order_wait_select_expired",
		Amount:    1,
		Currency:  "CNY",
		Status:    mdb.StatusWaitSelect,
		NotifyUrl: "https://merchant.example/callback",
	}
	if err := dao.Mdb.Create(placeholder).Error; err != nil {
		t.Fatalf("create placeholder order: %v", err)
	}
	if err := dao.Mdb.Model(placeholder).UpdateColumn("created_at", time.Now().Add(-20*time.Minute)).Error; err != nil {
		t.Fatalf("age placeholder order: %v", err)
	}

	processExpiredOrders()

	expired, err := data.GetOrderInfoByTradeId(order.TradeId)
	if err != nil {
		t.Fatalf("reload expired order: %v", err)
	}
	if expired.Status != mdb.StatusExpired {
		t.Fatalf("expired order status = %d, want %d", expired.Status, mdb.StatusExpired)
	}
	lockTradeID, err := data.GetTradeIdByWalletAddressAndAmountAndToken("tron", order.ReceiveAddress, order.Token, order.ActualAmount)
	if err != nil {
		t.Fatalf("expired order lock lookup: %v", err)
	}
	if lockTradeID != "" {
		t.Fatalf("expired order lock still exists: %s", lockTradeID)
	}

	recent, err := data.GetOrderInfoByTradeId(recentOrder.TradeId)
	if err != nil {
		t.Fatalf("reload recent order: %v", err)
	}
	if recent.Status != mdb.StatusWaitPay {
		t.Fatalf("recent order status = %d, want %d", recent.Status, mdb.StatusWaitPay)
	}
	lockTradeID, err = data.GetTradeIdByWalletAddressAndAmountAndToken("tron", recentOrder.ReceiveAddress, recentOrder.Token, recentOrder.ActualAmount)
	if err != nil {
		t.Fatalf("recent order lock lookup: %v", err)
	}
	if lockTradeID != recentOrder.TradeId {
		t.Fatalf("recent order lock = %s, want %s", lockTradeID, recentOrder.TradeId)
	}

	expiredPlaceholder, err := data.GetOrderInfoByTradeId(placeholder.TradeId)
	if err != nil {
		t.Fatalf("reload expired placeholder: %v", err)
	}
	if expiredPlaceholder.Status != mdb.StatusExpired {
		t.Fatalf("placeholder status = %d, want %d", expiredPlaceholder.Status, mdb.StatusExpired)
	}
}

func TestProcessExpiredOrdersKeepsPaidOrdersPaid(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	order := &mdb.Orders{
		TradeId:            "trade_paid",
		OrderId:            "order_paid",
		Amount:             1,
		Currency:           "CNY",
		ActualAmount:       1,
		ReceiveAddress:     "wallet_1",
		Token:              "USDT",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          "https://merchant.example/callback",
		BlockTransactionId: "block_paid",
		CallBackConfirm:    mdb.CallBackConfirmNo,
	}
	if err := dao.Mdb.Create(order).Error; err != nil {
		t.Fatalf("create paid order: %v", err)
	}
	if err := dao.Mdb.Model(order).UpdateColumn("created_at", time.Now().Add(-20*time.Minute)).Error; err != nil {
		t.Fatalf("age paid order: %v", err)
	}

	processExpiredOrders()

	current, err := data.GetOrderInfoByTradeId(order.TradeId)
	if err != nil {
		t.Fatalf("reload paid order: %v", err)
	}
	if current.Status != mdb.StatusPaySuccess {
		t.Fatalf("paid order status = %d, want %d", current.Status, mdb.StatusPaySuccess)
	}
	if current.BlockTransactionId != "block_paid" {
		t.Fatalf("paid order block transaction id = %s, want block_paid", current.BlockTransactionId)
	}
}

func TestDispatchPendingCallbacksHonorsBackoffAndPersistsSuccess(t *testing.T) {
	setupGMPayCallbackTest(t)

	callbackLimiter = make(chan struct{}, 1)
	callbackInflight = sync.Map{}

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	order := &mdb.Orders{
		TradeId:            "trade_callback",
		OrderId:            "order_callback",
		Amount:             1,
		Currency:           "CNY",
		ActualAmount:       1,
		ReceiveAddress:     "wallet_1",
		Token:              "USDT",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          server.URL,
		BlockTransactionId: "block_callback",
		CallbackNum:        1,
		CallBackConfirm:    mdb.CallBackConfirmNo,
		ApiKeyID:           1, // seeded by testutil.SetupTestDatabases
	}
	if err := dao.Mdb.Create(order).Error; err != nil {
		t.Fatalf("create callback order: %v", err)
	}

	dispatchPendingCallbacks()
	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadInt32(&requestCount); got != 0 {
		t.Fatalf("unexpected callback count before backoff elapsed: %d", got)
	}

	if err := dao.Mdb.Model(order).UpdateColumn("updated_at", time.Now().Add(-2*time.Second)).Error; err != nil {
		t.Fatalf("age callback order: %v", err)
	}
	dispatchPendingCallbacks()

	waitFor(t, 3*time.Second, func() bool {
		current, err := data.GetOrderInfoByTradeId(order.TradeId)
		if err != nil || current.ID <= 0 {
			return false
		}
		return current.CallBackConfirm == mdb.CallBackConfirmOk && current.CallbackNum == 2
	})

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("callback request count = %d, want 1", got)
	}
}

func TestDispatchPendingCallbacksResumesRetryAfterRestart(t *testing.T) {
	setupGMPayCallbackTest(t)

	callbackLimiter = make(chan struct{}, 1)
	callbackInflight = sync.Map{}

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&requestCount, 1)
		if attempt == 1 {
			http.Error(w, "retry later", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	order := &mdb.Orders{
		TradeId:            "trade_callback_restart",
		OrderId:            "order_callback_restart",
		Amount:             1,
		Currency:           "CNY",
		ActualAmount:       1,
		ReceiveAddress:     "wallet_restart",
		Token:              "USDT",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          server.URL,
		BlockTransactionId: "block_callback_restart",
		CallbackNum:        0,
		CallBackConfirm:    mdb.CallBackConfirmNo,
		ApiKeyID:           1, // seeded by testutil.SetupTestDatabases
	}
	if err := dao.Mdb.Create(order).Error; err != nil {
		t.Fatalf("create callback order: %v", err)
	}

	dispatchPendingCallbacks()

	waitFor(t, 3*time.Second, func() bool {
		current, err := data.GetOrderInfoByTradeId(order.TradeId)
		if err != nil || current.ID <= 0 {
			return false
		}
		return current.CallBackConfirm == mdb.CallBackConfirmNo && current.CallbackNum == 1
	})

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("first callback request count = %d, want 1", got)
	}

	callbackLimiter = make(chan struct{}, 1)
	callbackInflight = sync.Map{}

	if err := dao.Mdb.Model(order).UpdateColumn("updated_at", time.Now().Add(-2*time.Second)).Error; err != nil {
		t.Fatalf("age callback order for retry: %v", err)
	}

	dispatchPendingCallbacks()

	waitFor(t, 3*time.Second, func() bool {
		current, err := data.GetOrderInfoByTradeId(order.TradeId)
		if err != nil || current.ID <= 0 {
			return false
		}
		return current.CallBackConfirm == mdb.CallBackConfirmOk && current.CallbackNum == 2
	})

	if got := atomic.LoadInt32(&requestCount); got != 2 {
		t.Fatalf("total callback request count = %d, want 2", got)
	}
}

func TestDispatchPendingCallbacksEpayRequiresAck(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	callbackLimiter = make(chan struct{}, 1)
	callbackInflight = sync.Map{}

	epayKey, err := data.GetEnabledApiKey("1001")
	if err != nil || epayKey == nil || epayKey.ID == 0 {
		t.Fatalf("load epay key: %v", err)
	}

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer server.Close()

	order := &mdb.Orders{
		TradeId:            "trade_callback_epay_fail",
		OrderId:            "order_callback_epay_fail",
		Amount:             1,
		Currency:           "CNY",
		ActualAmount:       1,
		ReceiveAddress:     "wallet_epay_fail",
		Token:              "USDT",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          server.URL,
		BlockTransactionId: "block_callback_epay_fail",
		CallbackNum:        0,
		CallBackConfirm:    mdb.CallBackConfirmNo,
		PaymentType:        "epay",
		ApiKeyID:           epayKey.ID,
	}
	if err := dao.Mdb.Create(order).Error; err != nil {
		t.Fatalf("create callback order: %v", err)
	}

	dispatchPendingCallbacks()

	waitFor(t, 3*time.Second, func() bool {
		current, innerErr := data.GetOrderInfoByTradeId(order.TradeId)
		if innerErr != nil || current.ID <= 0 {
			return false
		}
		return current.CallBackConfirm == mdb.CallBackConfirmNo && current.CallbackNum == 1
	})

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("callback request count = %d, want 1", got)
	}
}

func TestDispatchPendingCallbacksEpayAcceptsTrimmedOk(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	callbackLimiter = make(chan struct{}, 1)
	callbackInflight = sync.Map{}

	epayKey, err := data.GetEnabledApiKey("1001")
	if err != nil || epayKey == nil || epayKey.ID == 0 {
		t.Fatalf("load epay key: %v", err)
	}

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_, _ = io.WriteString(w, " ok\n")
	}))
	defer server.Close()

	order := &mdb.Orders{
		TradeId:            "trade_callback_epay_ok",
		OrderId:            "order_callback_epay_ok",
		Amount:             1,
		Currency:           "CNY",
		ActualAmount:       1,
		ReceiveAddress:     "wallet_epay_ok",
		Token:              "USDT",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          server.URL,
		BlockTransactionId: "block_callback_epay_ok",
		CallbackNum:        0,
		CallBackConfirm:    mdb.CallBackConfirmNo,
		PaymentType:        "epay",
		ApiKeyID:           epayKey.ID,
	}
	if err := dao.Mdb.Create(order).Error; err != nil {
		t.Fatalf("create callback order: %v", err)
	}

	dispatchPendingCallbacks()

	waitFor(t, 3*time.Second, func() bool {
		current, innerErr := data.GetOrderInfoByTradeId(order.TradeId)
		if innerErr != nil || current.ID <= 0 {
			return false
		}
		return current.CallBackConfirm == mdb.CallBackConfirmOk && current.CallbackNum == 1
	})

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("callback request count = %d, want 1", got)
	}
}

// Orders must always carry an ApiKeyID (the default key is seeded at
// bootstrap and the signing middleware / EPAY inline flow always
// stamps it). If ApiKeyID is 0, resolveOrderApiKey returns an error —
// the callback won't sign with a guess.
func TestResolveOrderApiKeyRejectsZeroApiKeyID(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	order := &mdb.Orders{
		TradeId:  "no-api-key-id",
		ApiKeyID: 0,
	}
	if _, err := resolveOrderApiKey(order); err == nil {
		t.Fatal("expected error for ApiKeyID=0")
	}
}

// Happy path: when ApiKeyID points at an enabled row, resolveOrderApiKey
// returns it.
func TestResolveOrderApiKeyReturnsEnabledRow(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	row := &mdb.ApiKey{
		Name:      "target",
		Pid:       "target-key",
		SecretKey: "target-secret",
		Status:    mdb.ApiKeyStatusEnable,
	}
	if err := dao.Mdb.Create(row).Error; err != nil {
		t.Fatalf("create api key: %v", err)
	}
	order := &mdb.Orders{
		TradeId:  "happy-path",
		ApiKeyID: row.ID,
	}
	got, err := resolveOrderApiKey(order)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.ID != row.ID {
		t.Fatalf("resolved row = %+v, want id=%d", got, row.ID)
	}
}

func TestSendOrderCallbackGmpayNotifyIsEd25519Signed(t *testing.T) {
	priv := setupGMPayCallbackTest(t)
	pub := priv.Public().(ed25519.PublicKey)

	key := &mdb.ApiKey{
		Name:      "gmpay-ed25519-key",
		Pid:       "9001",
		SecretKey: "hmac-secret-must-not-sign-callbacks",
		Status:    mdb.ApiKeyStatusEnable,
	}
	if err := dao.Mdb.Create(key).Error; err != nil {
		t.Fatalf("create gmpay api key: %v", err)
	}

	var method, contentType string
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		contentType = r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	order := &mdb.Orders{
		TradeId:            "trade_gmpay_ed25519",
		OrderId:            "order_gmpay_ed25519",
		Amount:             100,
		Currency:           "CNY",
		ActualAmount:       14.2857,
		ReceiveAddress:     "wallet_gmpay_ed25519",
		Token:              "USDT",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          server.URL,
		BlockTransactionId: "block_gmpay_ed25519",
		ApiKeyID:           key.ID,
		PaymentType:        mdb.PaymentTypeGmpay,
	}

	if err := sendOrderCallback(order); err != nil {
		t.Fatalf("send callback: %v", err)
	}

	if method != http.MethodPost {
		t.Fatalf("callback method = %s, want %s", method, http.MethodPost)
	}
	if contentType != "application/json" {
		t.Fatalf("callback content type = %q, want application/json", contentType)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode callback body %q: %v", body, err)
	}

	// A successful payment still reports the business fields the merchant needs.
	if got, _ := payload["pid"].(string); got != key.Pid {
		t.Fatalf("payload pid = %q, want %q", got, key.Pid)
	}
	if got, _ := payload["trade_id"].(string); got != order.TradeId {
		t.Fatalf("payload trade_id = %q, want %q", got, order.TradeId)
	}
	if got, _ := payload["order_id"].(string); got != order.OrderId {
		t.Fatalf("payload order_id = %q, want %q", got, order.OrderId)
	}
	if got, _ := payload["amount"].(float64); got != order.Amount {
		t.Fatalf("payload amount = %v, want %v", got, order.Amount)
	}
	if got, _ := payload["actual_amount"].(float64); got != order.ActualAmount {
		t.Fatalf("payload actual_amount = %v, want %v", got, order.ActualAmount)
	}
	if got, _ := payload["receive_address"].(string); got != order.ReceiveAddress {
		t.Fatalf("payload receive_address = %q, want %q", got, order.ReceiveAddress)
	}
	if got, _ := payload["token"].(string); got != order.Token {
		t.Fatalf("payload token = %q, want %q", got, order.Token)
	}
	if got, _ := payload["block_transaction_id"].(string); got != order.BlockTransactionId {
		t.Fatalf("payload block_transaction_id = %q, want %q", got, order.BlockTransactionId)
	}
	if got, _ := payload["status"].(float64); got != float64(mdb.StatusPaySuccess) {
		t.Fatalf("payload status = %v, want %d", got, mdb.StatusPaySuccess)
	}
	if _, ok := payload["payment_type"]; ok {
		t.Fatal("GMPay callback payload must not include payment_type")
	}

	// sign_type and key_id are part of the signed payload.
	if got, _ := payload["sign_type"].(string); got != "ed25519" {
		t.Fatalf("payload sign_type = %q, want ed25519", got)
	}
	wantKeyID := hex.EncodeToString(pub)[:8]
	if got, _ := payload["key_id"].(string); got != wantKeyID {
		t.Fatalf("payload key_id = %q, want %q", got, wantKeyID)
	}

	// Verify the bytes the sender actually handed to the HTTP client. The
	// canonical form is recomputed here from the wire bytes with an independent
	// implementation of the protocol rules.
	signatureHex, _ := payload["signature"].(string)
	if signatureHex == "" {
		t.Fatal("payload signature is empty")
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatalf("payload signature is not hex: %v", err)
	}
	if !ed25519.Verify(pub, []byte(canonicalNotifyParams(t, payload)), signature) {
		t.Fatalf("wire bytes do not carry a valid Ed25519 signature: %s", body)
	}

	// Every signed field must be covered: changing one and keeping the signature
	// must break verification.
	for _, tamper := range []struct {
		field string
		apply func(map[string]interface{})
	}{
		{"sign_type", func(p map[string]interface{}) { p["sign_type"] = "hmac" }},
		{"key_id", func(p map[string]interface{}) { p["key_id"] = "00000000" }},
		{"amount", func(p map[string]interface{}) { p["amount"] = 999999.0 }},
		{"order_id", func(p map[string]interface{}) { p["order_id"] = "tampered-order-id" }},
	} {
		t.Run("tampered "+tamper.field, func(t *testing.T) {
			tampered := maps.Clone(payload)
			tamper.apply(tampered)
			if ed25519.Verify(pub, []byte(canonicalNotifyParams(t, tampered)), signature) {
				t.Fatalf("signature still verifies after changing %s", tamper.field)
			}
		})
	}
}

// setupGMPayCallbackTest prepares the test databases and loads a fixed Ed25519
// seed as the GMPay signing key through config.Init(), the same path production
// uses. Callbacks sign with the configured key, so without it the worker refuses
// to send anything.
func setupGMPayCallbackTest(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	cleanup := testutil.SetupTestDatabases(t)
	t.Cleanup(cleanup)

	const seed = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
	priv, err := sign.PrivateKeyFromSeedHex(seed)
	if err != nil {
		t.Fatalf("derive test signing key: %v", err)
	}

	envPath := filepath.Join(t.TempDir(), ".env")
	env := strings.Join([]string{
		"log_level=error",
		"gmpay_signing_key=" + seed,
		"gmpay_reconcile_key=reconcile-test-key-0123456789abcdef",
	}, "\n")
	if err = os.WriteFile(envPath, []byte(env), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	config.SetConfigPath(envPath)
	t.Cleanup(func() { config.SetConfigPath("") })
	config.Init()

	return priv
}

// canonicalNotifyParams reimplements the wire canonicalisation instead of
// calling util/sign, so the assertion does not share the implementation under
// test: drop signature/nil/empty strings, render float64 with FormatFloat,
// sort the k=v pairs and join them with "&".
func canonicalNotifyParams(t *testing.T, payload map[string]interface{}) string {
	t.Helper()

	parts := make([]string, 0, len(payload))
	for key, value := range payload {
		if key == "signature" || value == nil {
			continue
		}
		switch v := value.(type) {
		case string:
			if v == "" {
				continue
			}
			parts = append(parts, key+"="+v)
		case float64:
			parts = append(parts, key+"="+strconv.FormatFloat(v, 'f', -1, 64))
		case bool:
			parts = append(parts, key+"="+strconv.FormatBool(v))
		default:
			t.Fatalf("unexpected callback payload type %T for %q", value, key)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func TestSendOrderCallbackEpayUsesApiKeySecretByPid(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	key := &mdb.ApiKey{
		Name:      "epay-key",
		Pid:       "9101",
		SecretKey: "epay-secret-9101",
		Status:    mdb.ApiKeyStatusEnable,
	}
	if err := dao.Mdb.Create(key).Error; err != nil {
		t.Fatalf("create epay api key: %v", err)
	}

	warningKey := &mdb.ApiKey{
		Name:      "wrong-epay-key",
		Pid:       "9102",
		SecretKey: "wrong-epay-secret-9102",
		Status:    mdb.ApiKeyStatusEnable,
	}
	if err := dao.Mdb.Create(warningKey).Error; err != nil {
		t.Fatalf("create wrong epay api key: %v", err)
	}

	formPayload := map[string]string{}
	callbackMethod := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbackMethod = r.Method
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range r.Form {
			if len(v) > 0 {
				formPayload[k] = v[0]
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	order := &mdb.Orders{
		TradeId:            "trade_epay_sign",
		OrderId:            "order_epay_sign",
		Amount:             1,
		Currency:           "CNY",
		ActualAmount:       1,
		ReceiveAddress:     "wallet_epay",
		Token:              "USDT",
		Name:               "VIP",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          server.URL,
		BlockTransactionId: "block_epay_sign",
		EpayType:           "usdt.tron",
		PaymentType:        "epay",
		ApiKeyID:           key.ID,
	}

	if err := sendOrderCallback(order); err != nil {
		t.Fatalf("send epay callback: %v", err)
	}

	if callbackMethod != http.MethodGet {
		t.Fatalf("callback method = %s, want %s", callbackMethod, http.MethodGet)
	}
	if formPayload["sign_type"] != "MD5" {
		t.Fatalf("sign_type = %q, want MD5", formPayload["sign_type"])
	}
	if formPayload["type"] != "usdt.tron" {
		t.Fatalf("type = %q, want usdt.tron", formPayload["type"])
	}
	if formPayload["trade_status"] != "TRADE_SUCCESS" {
		t.Fatalf("trade_status = %q, want TRADE_SUCCESS", formPayload["trade_status"])
	}
	if _, ok := formPayload["payment_type"]; ok {
		t.Fatal("EPay callback payload must not include payment_type")
	}

	if formPayload["pid"] != key.Pid {
		t.Fatalf("form pid = %q, want %q", formPayload["pid"], key.Pid)
	}
	recvSig := formPayload["sign"]
	if recvSig == "" {
		t.Fatal("epay sign is empty")
	}

	signParams := map[string]interface{}{
		"pid":          formPayload["pid"],
		"trade_no":     formPayload["trade_no"],
		"out_trade_no": formPayload["out_trade_no"],
		"type":         formPayload["type"],
		"name":         formPayload["name"],
		"money":        formPayload["money"],
		"trade_status": formPayload["trade_status"],
	}

	calcSig, err := sign.Get(signParams, key.SecretKey)
	if err != nil {
		t.Fatalf("calc epay signature with target secret: %v", err)
	}
	if recvSig != calcSig {
		t.Fatalf("epay signature mismatch: got %q want %q", recvSig, calcSig)
	}

	wrongSig, err := sign.Get(signParams, warningKey.SecretKey)
	if err != nil {
		t.Fatalf("calc epay signature with wrong secret: %v", err)
	}
	if recvSig == wrongSig {
		t.Fatal("epay signature should not match wrong api key secret")
	}
}

func TestSendOrderCallbackEpayPreservesStoredAlipayType(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	key := &mdb.ApiKey{
		Name:      "epay-key-stored-type",
		Pid:       "9201",
		SecretKey: "epay-secret-9201",
		Status:    mdb.ApiKeyStatusEnable,
	}
	if err := dao.Mdb.Create(key).Error; err != nil {
		t.Fatalf("create epay api key: %v", err)
	}

	formPayload := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range r.Form {
			if len(v) > 0 {
				formPayload[k] = v[0]
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	order := &mdb.Orders{
		TradeId:            "trade_epay_type_case_alipay",
		OrderId:            "order_epay_type_case_alipay",
		Amount:             1,
		Currency:           "CNY",
		ActualAmount:       1,
		ReceiveAddress:     "wallet_epay_type_case",
		Token:              "USDT",
		Name:               "VIP",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          server.URL,
		BlockTransactionId: "block_epay_type_case_alipay",
		EpayType:           "alipay",
		PaymentType:        "epay",
		ApiKeyID:           key.ID,
	}

	if err := sendOrderCallback(order); err != nil {
		t.Fatalf("send epay callback: %v", err)
	}
	if got := formPayload["type"]; got != "alipay" {
		t.Fatalf("type = %q, want alipay", got)
	}

	signParams := map[string]interface{}{
		"pid":          formPayload["pid"],
		"trade_no":     formPayload["trade_no"],
		"out_trade_no": formPayload["out_trade_no"],
		"type":         formPayload["type"],
		"name":         formPayload["name"],
		"money":        formPayload["money"],
		"trade_status": formPayload["trade_status"],
	}
	calcSig, err := sign.Get(signParams, key.SecretKey)
	if err != nil {
		t.Fatalf("calc epay signature: %v", err)
	}
	if got := formPayload["sign"]; got != calcSig {
		t.Fatalf("sign = %q, want %q", got, calcSig)
	}
}

func TestDispatchPendingCallbacksEpayAcceptsSuccessAck(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	callbackLimiter = make(chan struct{}, 1)
	callbackInflight = sync.Map{}

	epayKey, err := data.GetEnabledApiKey("1001")
	if err != nil || epayKey == nil || epayKey.ID == 0 {
		t.Fatalf("load epay key: %v", err)
	}

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_, _ = io.WriteString(w, "success")
	}))
	defer server.Close()

	order := &mdb.Orders{
		TradeId:            "trade_callback_epay_success",
		OrderId:            "order_callback_epay_success",
		Amount:             1,
		Currency:           "CNY",
		ActualAmount:       1,
		ReceiveAddress:     "wallet_epay_success",
		Token:              "USDT",
		Status:             mdb.StatusPaySuccess,
		NotifyUrl:          server.URL,
		BlockTransactionId: "block_callback_epay_success",
		CallbackNum:        0,
		CallBackConfirm:    mdb.CallBackConfirmNo,
		PaymentType:        mdb.PaymentTypeEpay,
		ApiKeyID:           epayKey.ID,
	}
	if err := dao.Mdb.Create(order).Error; err != nil {
		t.Fatalf("create callback order: %v", err)
	}

	dispatchPendingCallbacks()

	waitFor(t, 3*time.Second, func() bool {
		current, innerErr := data.GetOrderInfoByTradeId(order.TradeId)
		if innerErr != nil || current.ID <= 0 {
			return false
		}
		return current.CallBackConfirm == mdb.CallBackConfirmOk && current.CallbackNum == 1
	})

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("callback request count = %d, want 1", got)
	}
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not satisfied before timeout")
}

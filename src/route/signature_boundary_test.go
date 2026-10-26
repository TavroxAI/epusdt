package route

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/util/sign"
)

// signedFormValues signs a submitted form body the way a merchant would: over the
// parameters it actually sends.
func signedFormValues(t *testing.T, values url.Values) url.Values {
	t.Helper()

	params := make(map[string]interface{}, len(values))
	for key, items := range values {
		if len(items) == 0 || key == "signature" {
			continue
		}
		params[key] = items[0]
	}
	signature, err := sign.GetHMACSHA256(params, testAPIToken)
	if err != nil {
		t.Fatalf("sign form body: %v", err)
	}
	values.Set("signature", signature)
	return values
}

func gmpayFormBody(orderID string, amount string) url.Values {
	return url.Values{
		"pid":          {testAPIToken},
		"order_id":     {orderID},
		"amount":       {amount},
		"currency":     {"cny"},
		"token":        {"usdt"},
		"network":      {"solana"},
		"notify_url":   {"https://93.184.216.34/notify"},
		"redirect_url": {"https://merchant.example/return"},
	}
}

// orderExists reports whether an order with the given merchant order id exists.
func orderExists(t *testing.T, orderID string) bool {
	t.Helper()

	var order mdb.Orders
	if err := dao.Mdb.Where("order_id = ?", orderID).Limit(1).Find(&order).Error; err != nil {
		t.Fatalf("look up order %q: %v", orderID, err)
	}
	return order.ID != 0
}

// TestCreateOrderRejectsUnsignedQueryOverride covers vuln-0007: the signature was
// computed over the body while the handler bound body and query together, so a
// request signed for amount=100.00 could create an order for 0.01.
func TestCreateOrderRejectsUnsignedQueryOverride(t *testing.T) {
	e := setupTestEnv(t)
	useRspErrorHTTPStatuses(e)

	values := signedFormValues(t, gmpayFormBody("sig-query-override-1", "100.00"))
	rec := doFormPost(e, "/payments/gmpay/v1/order/create-transaction?amount=0.01", values)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if orderExists(t, "sig-query-override-1") {
		t.Fatal("order was created despite an unsigned amount override")
	}
}

// TestCreateOrderRejectsCaseVariantDuplicate covers the case-sensitivity half of
// vuln-0007: a body signed as AMOUNT=100.00 combined with ?amount=0.01 used to
// reach the handler as 0.01 because Echo binds an exact-case match.
func TestCreateOrderRejectsCaseVariantDuplicate(t *testing.T) {
	e := setupTestEnv(t)
	useRspErrorHTTPStatuses(e)

	t.Run("body and query", func(t *testing.T) {
		values := url.Values{
			"pid":          {testAPIToken},
			"order_id":     {"sig-case-body-query-1"},
			"AMOUNT":       {"100.00"},
			"currency":     {"cny"},
			"token":        {"usdt"},
			"network":      {"solana"},
			"notify_url":   {"https://93.184.216.34/notify"},
			"redirect_url": {"https://merchant.example/return"},
		}
		values = signedFormValues(t, values)

		rec := doFormPost(e, "/payments/gmpay/v1/order/create-transaction?amount=0.01", values)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
		}
		if orderExists(t, "sig-case-body-query-1") {
			t.Fatal("order was created from an ambiguous amount")
		}
	})

	t.Run("two spellings in the body", func(t *testing.T) {
		values := url.Values{
			"pid":          {testAPIToken},
			"order_id":     {"sig-case-body-1"},
			"AMOUNT":       {"100.00"},
			"amount":       {"0.01"},
			"currency":     {"cny"},
			"token":        {"usdt"},
			"network":      {"solana"},
			"notify_url":   {"https://93.184.216.34/notify"},
			"redirect_url": {"https://merchant.example/return"},
		}
		values = signedFormValues(t, values)

		rec := doFormPost(e, "/payments/gmpay/v1/order/create-transaction", values)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
		}
		if orderExists(t, "sig-case-body-1") {
			t.Fatal("order was created from an ambiguous amount")
		}
	})
}

// TestCreateOrderRejectsUnsignedExtraParameter covers the rest of the class: any
// parameter the handler can bind must be inside the signature, so an unsigned
// redirect_url, payment_type or token in the query is refused.
func TestCreateOrderRejectsUnsignedExtraParameter(t *testing.T) {
	e := setupTestEnv(t)
	useRspErrorHTTPStatuses(e)

	for name, query := range map[string]string{
		"redirect_url": "?redirect_url=https://attacker.example/x",
		"payment_type": "?payment_type=Epay",
		"token":        "?token=usdc",
	} {
		t.Run(name, func(t *testing.T) {
			values := signedFormValues(t, gmpayFormBody("sig-extra-"+name, "1.00"))
			rec := doFormPost(e, "/payments/gmpay/v1/order/create-transaction"+query, values)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestCreateOrderAllowsIdenticalRepeat keeps the guard from over-reaching: the
// same key with the same value in both places is unambiguous and still accepted.
func TestCreateOrderAllowsIdenticalRepeat(t *testing.T) {
	e := setupTestEnv(t)
	useRspErrorHTTPStatuses(e)

	values := signedFormValues(t, gmpayFormBody("sig-identical-repeat-1", "1.00"))
	rec := doFormPost(e, "/payments/gmpay/v1/order/create-transaction?amount=1.00", values)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// TestApiKeyIPAllowlistIgnoresForwardedHeader covers vuln-0008: the allow-list was
// evaluated against X-Forwarded-For, so a non-allow-listed caller could name the
// allow-listed address and get through.
func TestApiKeyIPAllowlistIgnoresForwardedHeader(t *testing.T) {
	e := setupTestEnv(t)
	useRspErrorHTTPStatuses(e)

	if err := dao.Mdb.Model(&mdb.ApiKey{}).
		Where("pid = ?", testAPIToken).
		Update("ip_whitelist", "198.51.100.7").Error; err != nil {
		t.Fatalf("restrict api key ip whitelist: %v", err)
	}

	post := func(orderID string) *httptest.ResponseRecorder {
		body := signBody(map[string]interface{}{
			"order_id":   orderID,
			"amount":     1.00,
			"token":      "usdt",
			"currency":   "cny",
			"network":    "solana",
			"notify_url": "https://93.184.216.34/notify",
		})
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/payments/gmpay/v1/order/create-transaction", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		// The caller claims to be the allow-listed address.
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		req.Header.Set("X-Real-IP", "198.51.100.7")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	rec := post("ip-spoof-1")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged X-Forwarded-For passed the allow-list: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// The real peer is 192.0.2.1; allow-listing it makes the same request pass,
	// which proves the check itself still runs.
	if err := dao.Mdb.Model(&mdb.ApiKey{}).
		Where("pid = ?", testAPIToken).
		Update("ip_whitelist", "192.0.2.1").Error; err != nil {
		t.Fatalf("allow-list the test peer: %v", err)
	}
	rec = post("ip-spoof-2")
	if rec.Code != http.StatusOK {
		t.Fatalf("allow-listed peer rejected: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

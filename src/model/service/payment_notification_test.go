package service

import (
	"strings"
	"testing"

	"github.com/GMWalletApp/epusdt/internal/testutil"
	"github.com/GMWalletApp/epusdt/model/mdb"
)

func paymentNoticeOrder(orderID string) *mdb.Orders {
	// The timestamps stay at their zero value: this test is about escaping the
	// merchant-controlled fields, not about the rendered times.
	return &mdb.Orders{
		TradeId:        "trade_1",
		OrderId:        orderID,
		Amount:         10,
		Currency:       "cny",
		ActualAmount:   1.42,
		Token:          "usdt",
		Network:        "tron",
		ReceiveAddress: "TXyz1",
	}
}

// TestBuildPaymentSuccessMessageEscapesMerchantFields covers vuln-0020: the alert
// is rendered with parse_mode=HTML, so merchant-controlled values must be escaped
// instead of becoming markup in the operator's feed.
func TestBuildPaymentSuccessMessageEscapesMerchantFields(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	msg := buildPaymentSuccessMessage(paymentNoticeOrder(`<a href="https://evil.example">PAY</a>`))

	if strings.Contains(msg, `<a href="https://evil.example">`) {
		t.Fatalf("merchant markup was rendered into the HTML message:\n%s", msg)
	}
	if !strings.Contains(msg, "&lt;a href=&#34;https://evil.example&#34;&gt;") {
		t.Fatalf("expected the order id to be escaped:\n%s", msg)
	}
	// The formatting the bot adds itself must survive.
	if !strings.Contains(msg, "<b>") || !strings.Contains(msg, "<code>trade_1</code>") {
		t.Fatalf("internal markup was lost:\n%s", msg)
	}
}

// TestBuildPaymentSuccessMessageEscapesTokenAndCurrency keeps the same rule for
// the other merchant-influenced fields.
func TestBuildPaymentSuccessMessageEscapesTokenAndCurrency(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	order := paymentNoticeOrder("order_2")
	order.Currency = "c<ny"
	order.Token = "us&dt"

	msg := buildPaymentSuccessMessage(order)
	if strings.Contains(msg, "<ny") || strings.Contains(msg, "us&dt") {
		t.Fatalf("unescaped currency/token reached the HTML message:\n%s", msg)
	}
	if !strings.Contains(msg, "C&lt;NY") || !strings.Contains(msg, "US&amp;DT") {
		t.Fatalf("expected escaped currency/token:\n%s", msg)
	}
}

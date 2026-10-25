package service

import (
	"testing"

	"github.com/GMWalletApp/epusdt/internal/testutil"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"

	"github.com/shopspring/decimal"
)

func TestTokenMinimumOrderAmount(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	stable := &mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "USDT", ContractAddress: "0xdAC17F958D2ee523a2206206994597C13D831ec7"}
	if got := tokenMinimumOrderAmount(stable); !got.Equal(decimal.NewFromFloat(UsdtMinimumPaymentAmount)) {
		t.Fatalf("stablecoin floor = %s, want the historical %s", got, decimal.NewFromFloat(UsdtMinimumPaymentAmount))
	}

	override := *stable
	override.MinAmount = 5
	if got := tokenMinimumOrderAmount(&override); !got.Equal(decimal.NewFromInt(5)) {
		t.Fatalf("configured floor = %s, want 5", got)
	}

	native := &mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "ETH"}
	if got := tokenMinimumOrderAmount(native); !got.Equal(decimal.New(1, -int32(DefaultPrecisionForTest(t)))) {
		t.Fatalf("native floor = %s, want the smallest amount at the configured precision", got)
	}
	if err := data.SetSetting("system", mdb.SettingKeyAmountPrecision, "6", "int"); err != nil {
		t.Fatalf("set amount precision: %v", err)
	}
	if err := data.ReloadSettings(); err != nil {
		t.Fatalf("reload settings: %v", err)
	}
	if got := tokenMinimumOrderAmount(native); !got.Equal(decimal.New(1, -6)) {
		t.Fatalf("native floor at precision 6 = %s, want 0.000001", got)
	}
	// The stablecoin floor must not move with the global precision.
	if got := tokenMinimumOrderAmount(stable); !got.Equal(decimal.NewFromFloat(UsdtMinimumPaymentAmount)) {
		t.Fatalf("stablecoin floor after precision change = %s, want %s", got, decimal.NewFromFloat(UsdtMinimumPaymentAmount))
	}
}

// DefaultPrecisionForTest reports the precision the service starts with, so the
// native floor assertion does not hard-code the default.
func DefaultPrecisionForTest(t *testing.T) int {
	t.Helper()
	precision := data.GetAmountPrecision()
	if precision < data.MinAmountPrecision || precision > data.MaxAmountPrecision {
		t.Fatalf("unexpected amount precision %d", precision)
	}
	return precision
}

func TestChainTokenReadyForPaymentAllowsOnlyTheNativeCoinOnEvmChains(t *testing.T) {
	testCases := []struct {
		name  string
		token mdb.ChainToken
		want  bool
	}{
		{"ethereum ETH without contract", mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "eth"}, true},
		{"binance BNB without contract", mdb.ChainToken{Network: mdb.NetworkBsc, Symbol: "BNB"}, true},
		{"ethereum USDC without contract", mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "USDC"}, false},
		{"ethereum USDC with contract", mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "USDC", ContractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}, true},
		{"binance ETH is not BNB", mdb.ChainToken{Network: mdb.NetworkBsc, Symbol: "ETH"}, false},
		{"polygon without contract", mdb.ChainToken{Network: mdb.NetworkPolygon, Symbol: "POL"}, false},
		{"tron TRX without contract", mdb.ChainToken{Network: mdb.NetworkTron, Symbol: "TRX"}, true},
		{"tron USDT without contract", mdb.ChainToken{Network: mdb.NetworkTron, Symbol: "USDT"}, false},
		{"solana SOL without contract", mdb.ChainToken{Network: mdb.NetworkSolana, Symbol: "SOL"}, true},
		{"ton TON without contract", mdb.ChainToken{Network: mdb.NetworkTon, Symbol: "TON"}, true},
		{"empty symbol", mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "  "}, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ChainTokenReadyForPayment(testCase.token); got != testCase.want {
				t.Fatalf("ChainTokenReadyForPayment(%s/%s contract=%q) = %v, want %v",
					testCase.token.Network, testCase.token.Symbol, testCase.token.ContractAddress, got, testCase.want)
			}
		})
	}
}

func TestIsEvmNativeToken(t *testing.T) {
	testCases := []struct {
		name  string
		token mdb.ChainToken
		want  bool
	}{
		{"ethereum ETH", mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "ETH"}, true},
		{"ethereum ETH lowercase", mdb.ChainToken{Network: "Ethereum", Symbol: "eth"}, true},
		{"binance BNB", mdb.ChainToken{Network: mdb.NetworkBsc, Symbol: "BNB"}, true},
		{"ethereum ETH with contract", mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "ETH", ContractAddress: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"}, false},
		{"polygon POL", mdb.ChainToken{Network: mdb.NetworkPolygon, Symbol: "POL"}, false},
		{"ethereum WETH", mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "WETH"}, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := IsEvmNativeToken(testCase.token); got != testCase.want {
				t.Fatalf("IsEvmNativeToken(%s/%s contract=%q) = %v, want %v",
					testCase.token.Network, testCase.token.Symbol, testCase.token.ContractAddress, got, testCase.want)
			}
		})
	}
}

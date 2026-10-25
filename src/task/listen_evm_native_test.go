package task

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/GMWalletApp/epusdt/internal/testutil"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/mdb"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestLoadEvmNativeTokenRequiresTheCanonicalSymbol(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	// The seed configures ethereum USDT/USDC contracts only.
	if _, ok := loadEvmNativeToken(mdb.NetworkEthereum, "[TEST]"); ok {
		t.Fatal("loadEvmNativeToken() found a native row before one was configured")
	}

	// A contract-less row with an unrelated symbol must not enable the scanner:
	// nothing would ever report it.
	if err := dao.Mdb.Create(&mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "NOSCANNER", Decimals: 18, Enabled: true}).Error; err != nil {
		t.Fatalf("create non-native row: %v", err)
	}
	if _, ok := loadEvmNativeToken(mdb.NetworkEthereum, "[TEST]"); ok {
		t.Fatal("loadEvmNativeToken() accepted a contract-less row that is not the native coin")
	}

	native := &mdb.ChainToken{Network: mdb.NetworkEthereum, Symbol: "ETH", Decimals: 18, Enabled: true}
	if err := dao.Mdb.Create(native).Error; err != nil {
		t.Fatalf("create native row: %v", err)
	}
	token, ok := loadEvmNativeToken(mdb.NetworkEthereum, "[TEST]")
	if !ok {
		t.Fatal("loadEvmNativeToken() did not return the configured ETH row")
	}
	if token.ID != native.ID || token.Decimals != 18 {
		t.Fatalf("loadEvmNativeToken() = id=%d decimals=%d, want id=%d decimals=18", token.ID, token.Decimals, native.ID)
	}

	// BSC has its own native symbol, so the ETH row must not leak into it.
	if _, ok := loadEvmNativeToken(mdb.NetworkBsc, "[TEST]"); ok {
		t.Fatal("loadEvmNativeToken(bsc) reused the ethereum native row")
	}

	if err := dao.Mdb.Model(native).Update("enabled", false).Error; err != nil {
		t.Fatalf("disable native row: %v", err)
	}
	if _, ok := loadEvmNativeToken(mdb.NetworkEthereum, "[TEST]"); ok {
		t.Fatal("loadEvmNativeToken() used a disabled row")
	}
}

func TestEvmNativeTransfersInBlock(t *testing.T) {
	receiver := common.HexToAddress("0x3E9F73d52A595b744A028BCDD58111dAD2293887")
	stranger := common.HexToAddress("0x0000000000000000000000000000000000000001")
	contract := common.HexToAddress("0x0000000000000000000000000000000000000002")
	watched := &evmNativeWatchList{addrs: map[string]struct{}{"0x3e9f73d52a595b744a028bcdd58111dad2293887": {}}}

	paid := types.NewTx(&types.LegacyTx{To: &receiver, Value: big.NewInt(10_000_000_000_000_000)})
	zero := types.NewTx(&types.LegacyTx{To: &receiver, Value: big.NewInt(0)})
	elsewhere := types.NewTx(&types.LegacyTx{To: &stranger, Value: big.NewInt(5)})
	deploy := types.NewTx(&types.LegacyTx{To: nil, Value: big.NewInt(0)})
	tokenCall := types.NewTx(&types.LegacyTx{To: &contract, Value: big.NewInt(0)})

	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(7), Time: 1_700_000_000}).
		WithBody(types.Body{Transactions: []*types.Transaction{zero, deploy, elsewhere, paid, tokenCall}})

	transfers := evmNativeTransfersInBlock(block, watched)
	if len(transfers) != 1 {
		t.Fatalf("evmNativeTransfersInBlock() returned %d transfers, want 1", len(transfers))
	}
	got := transfers[0]
	if got.to != receiver {
		t.Fatalf("transfer recipient = %s, want %s", got.to.Hex(), receiver.Hex())
	}
	if got.value.Cmp(big.NewInt(10_000_000_000_000_000)) != 0 {
		t.Fatalf("transfer value = %s, want 10000000000000000", got.value)
	}
	if got.txHash != paid.Hash() {
		t.Fatalf("transfer hash = %s, want %s", got.txHash.Hex(), paid.Hash().Hex())
	}
	if got.blockTsMs != 1_700_000_000_000 {
		t.Fatalf("transfer block timestamp = %d, want 1700000000000", got.blockTsMs)
	}
}

// TestEvmNativeTransferSucceeded checks the receipt gate that keeps a failed
// native transfer from settling an order. A plain value transfer to an account
// that has never held a balance costs an extra 25,000 gas; a sender that assumes
// 21,000 produces exactly this failure.
func TestEvmNativeTransferSucceeded(t *testing.T) {
	transfer := evmNativeTransfer{txHash: common.HexToHash("0x" + strings.Repeat("a", 64))}
	testCases := []struct {
		name   string
		reader evmNativeReceiptReader
		want   bool
	}{
		{"successful transfer", fakeNativeReceipts{status: types.ReceiptStatusSuccessful}, true},
		{"failed transfer", fakeNativeReceipts{status: types.ReceiptStatusFailed}, false},
		{"missing receipt", fakeNativeReceipts{err: errors.New("not found")}, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := evmNativeTransferSucceeded(context.Background(), testCase.reader, "[TEST]", transfer); got != testCase.want {
				t.Fatalf("evmNativeTransferSucceeded() = %v, want %v", got, testCase.want)
			}
		})
	}
}

type fakeNativeReceipts struct {
	status uint64
	err    error
}

func (f fakeNativeReceipts) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &types.Receipt{Status: f.status}, nil
}

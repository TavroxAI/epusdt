package task

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestTransferConfirmed pins the settlement rule: a transfer in the chain head is
// not confirmed while the configured depth is higher.
func TestTransferConfirmed(t *testing.T) {
	tests := []struct {
		name  string
		block int64
		head  int64
		depth int
		want  bool
	}{
		{"depth1 at head", 100, 100, 1, true},
		{"depth3 at head", 100, 100, 3, false},
		{"depth3 one short", 99, 100, 3, false},
		{"depth3 exactly", 98, 100, 3, true},
		{"depth3 deeper", 90, 100, 3, true},
		{"future block", 101, 100, 3, false},
		{"zero block", 0, 100, 3, false},
		{"zero head", 10, 0, 3, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := transferConfirmed(tt.block, tt.head, tt.depth); got != tt.want {
				t.Fatalf("transferConfirmed(%d,%d,%d) = %v, want %v", tt.block, tt.head, tt.depth, got, tt.want)
			}
		})
	}
}

func TestConfirmedBlockNumber(t *testing.T) {
	if got := confirmedBlockNumber(100, 1); got != 100 {
		t.Fatalf("confirmedBlockNumber(100,1) = %d, want 100", got)
	}
	if got := confirmedBlockNumber(100, 3); got != 98 {
		t.Fatalf("confirmedBlockNumber(100,3) = %d, want 98", got)
	}
	if got := confirmedBlockNumber(2, 3); got != 0 {
		t.Fatalf("confirmedBlockNumber(2,3) = %d, want 0 (chain shorter than the depth)", got)
	}
	if got := confirmedBlockNumber(0, 3); got != 0 {
		t.Fatalf("confirmedBlockNumber(0,3) = %d, want 0", got)
	}
}

// TestEvmCreditQueueDefersUntilDepth is the regression for vuln-0010: an observed
// transfer must not settle until its block reaches the configured depth.
func TestEvmCreditQueueDefersUntilDepth(t *testing.T) {
	head := int64(101)
	queue := newEvmCreditQueue("ethereum", func(context.Context) (int64, error) { return head, nil })
	queue.depth = func(string) int { return 3 }

	credited := 0
	queue.Offer(100, func() { credited++ })

	// head=101, depth=3 => cutoff 99, so block 100 is still one confirmation short.
	if got := queue.Drain(context.Background()); got != 0 {
		t.Fatalf("drain credited %d transfers before depth was reached", got)
	}
	if credited != 0 {
		t.Fatalf("credit ran at head=101: %d", credited)
	}
	if queue.Len() != 1 {
		t.Fatalf("queue length = %d, want 1", queue.Len())
	}

	// head=102 => cutoff 100, the transfer settles.
	head = 102
	if got := queue.Drain(context.Background()); got != 1 {
		t.Fatalf("drain credited %d transfers, want 1", got)
	}
	if credited != 1 {
		t.Fatalf("credit count = %d, want 1", credited)
	}
	if queue.Len() != 0 {
		t.Fatalf("queue length = %d, want 0", queue.Len())
	}
}

// TestEvmCreditQueueFailsClosed covers the "no trustworthy head" case: nothing is
// settled on faith.
func TestEvmCreditQueueFailsClosed(t *testing.T) {
	calls := 0
	queue := newEvmCreditQueue("ethereum", func(context.Context) (int64, error) {
		return 0, errors.New("node unavailable")
	})
	queue.depth = func(string) int { return 1 }
	queue.Offer(100, func() { calls++ })

	if got := queue.Drain(context.Background()); got != 0 {
		t.Fatalf("drain settled %d transfers without a head", got)
	}
	if calls != 0 {
		t.Fatalf("credit ran without a head: %d", calls)
	}

	// A source that reports a zero head is treated the same way.
	zeroHead := newEvmCreditQueue("ethereum", func(context.Context) (int64, error) { return 0, nil })
	zeroHead.depth = func(string) int { return 1 }
	zeroHead.Offer(100, func() { calls++ })
	if got := zeroHead.Drain(context.Background()); got != 0 || calls != 0 {
		t.Fatalf("zero head settled %d transfers (calls=%d)", got, calls)
	}
}

// TestEvmCreditQueuePreservesOrder keeps settlements in arrival order.
func TestEvmCreditQueuePreservesOrder(t *testing.T) {
	head := int64(200)
	queue := newEvmCreditQueue("bsc", func(context.Context) (int64, error) { return head, nil })
	queue.depth = func(string) int { return 1 }

	order := make([]int, 0, 3)
	for i := 1; i <= 3; i++ {
		value := i
		queue.Offer(int64(100+i), func() { order = append(order, value) })
	}
	if got := queue.Drain(context.Background()); got != 3 {
		t.Fatalf("drain credited %d, want 3", got)
	}
	want := []int{1, 2, 3}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

// TestEvmCreditQueueRunDrains keeps the ticker loop wired to Drain.
func TestEvmCreditQueueRunDrains(t *testing.T) {
	head := int64(300)
	queue := newEvmCreditQueue("polygon", func(context.Context) (int64, error) { return head, nil })
	queue.depth = func(string) int { return 1 }

	credited := make(chan struct{}, 1)
	queue.Offer(250, func() { credited <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go queue.Run(ctx, 10*time.Millisecond)

	select {
	case <-credited:
	case <-time.After(2 * time.Second):
		t.Fatal("queue drain loop did not credit a confirmed transfer")
	}
}

// TestCreditConfirmedEvmERC20TransferIgnoresRemovedLog covers the reorg half: a
// log the chain has removed must not settle anything, and must not touch the node.
func TestCreditConfirmedEvmERC20TransferIgnoresRemovedLog(t *testing.T) {
	before := evmCreditQueueFor("ethereum").Len()

	logEntry := types.Log{
		Address:     common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
		Topics:      []common.Hash{transferEventHash, {}, common.BytesToHash(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes())},
		Data:        common.BigToHash(common.Big1).Bytes(),
		BlockNumber: 100,
		Removed:     true,
	}
	// A nil client proves the function returned before touching the node.
	creditConfirmedEvmERC20Transfer(nil, "ethereum", "[TEST]", logEntry, func(common.Address) bool { return true })

	if after := evmCreditQueueFor("ethereum").Len(); after != before {
		t.Fatalf("removed log was queued for credit: %d -> %d", before, after)
	}
}

// TestCreditConfirmedEvmERC20TransferIgnoresOtherLogs keeps unrelated logs and
// unwatched recipients out of the queue.
func TestCreditConfirmedEvmERC20TransferIgnoresOtherLogs(t *testing.T) {
	before := evmCreditQueueFor("plasma").Len()

	other := types.Log{
		Address:     common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Topics:      []common.Hash{common.HexToHash("0xdeadbeef")},
		Data:        common.BigToHash(common.Big1).Bytes(),
		BlockNumber: 100,
	}
	creditConfirmedEvmERC20Transfer(nil, "plasma", "[TEST]", other, func(common.Address) bool { return true })

	unwatched := types.Log{
		Address:     common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Topics:      []common.Hash{transferEventHash, {}, common.BytesToHash(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes())},
		Data:        common.BigToHash(common.Big1).Bytes(),
		BlockNumber: 100,
	}
	creditConfirmedEvmERC20Transfer(nil, "plasma", "[TEST]", unwatched, func(common.Address) bool { return false })

	if after := evmCreditQueueFor("plasma").Len(); after != before {
		t.Fatalf("irrelevant log was queued: %d -> %d", before, after)
	}
}

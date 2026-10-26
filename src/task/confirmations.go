package task

import (
	"context"
	"sync"
	"time"

	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/util/log"
)

// minConfirmationsFor returns the settlement depth configured for a network
// (chains.min_confirmations). A missing row or a nonsensical value means "settle
// on sight", which is the pre-existing behaviour for depth 1.
func minConfirmationsFor(network string) int {
	chain, err := data.GetChainByNetwork(network)
	if err != nil || chain == nil || chain.MinConfirmations <= 0 {
		return 1
	}
	return chain.MinConfirmations
}

// transferConfirmed reports whether a transfer seen in blockNumber is deep enough
// to settle at chain head. A transfer at the very tip is not confirmed: that is
// the whole point of the depth setting, since a reorg can still remove it.
func transferConfirmed(blockNumber, head int64, minConfirmations int) bool {
	if blockNumber <= 0 || head <= 0 || blockNumber > head {
		return false
	}
	if minConfirmations <= 1 {
		return true
	}
	return blockNumber <= head-int64(minConfirmations)+1
}

// confirmedBlockNumber returns the deepest block that may be settled at head.
func confirmedBlockNumber(head int64, minConfirmations int) int64 {
	if head <= 0 {
		return 0
	}
	if minConfirmations <= 1 {
		return head
	}
	if head < int64(minConfirmations)-1 {
		return 0
	}
	return head - int64(minConfirmations) + 1
}

// evmCreditQueue holds observed EVM transfers until the block carrying them is
// deep enough to settle.
//
// The websocket listeners observe a transfer the moment it lands, which used to
// mean crediting at zero confirmations: an order was marked paid, its amount
// reservation released and the merchant callback delivered before the block could
// still be reorganised away. Deferring the credit until the configured depth is
// reached removes that window for every reorg shallower than the configured
// depth.
type evmCreditQueue struct {
	network string

	// head returns the current chain head. It is a field so tests can drive the
	// queue without a node, and it fails closed: no head, no credit.
	head func(ctx context.Context) (int64, error)
	// depth returns the configured settlement depth for the network.
	depth func(network string) int

	mu    sync.Mutex
	items []evmPendingCredit
}

// evmPendingCredit is one transfer waiting for depth. credit is the closure that
// performs the settlement; it takes no arguments so the queue does not need to
// know about tokens, contracts or amounts.
type evmPendingCredit struct {
	block  int64
	credit func()
}

// maxPendingEvmCredits bounds the buffer. Reaching it means the chain head is not
// advancing (or the depth is absurdly large); dropping the oldest entries keeps
// memory bounded and the newest transfers are the ones still worth crediting.
const maxPendingEvmCredits = 5000

func newEvmCreditQueue(network string, head func(ctx context.Context) (int64, error)) *evmCreditQueue {
	return &evmCreditQueue{
		network: network,
		head:    head,
		depth:   minConfirmationsFor,
	}
}

// Offer queues a transfer for later settlement.
func (q *evmCreditQueue) Offer(block int64, credit func()) {
	if credit == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) >= maxPendingEvmCredits {
		dropped := q.items[0]
		q.items = q.items[1:]
		log.Sugar.Warnf("[EVM-DEPTH] queue full network=%s, dropping transfer from block=%d", q.network, dropped.block)
	}
	q.items = append(q.items, evmPendingCredit{block: block, credit: credit})
}

// Len reports how many transfers are waiting.
func (q *evmCreditQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Drain credits every queued transfer whose block has reached the configured
// depth, preserving arrival order. It returns how many were credited.
func (q *evmCreditQueue) Drain(ctx context.Context) int {
	if q.Len() == 0 {
		return 0
	}
	if q.head == nil {
		return 0
	}
	head, err := q.head(ctx)
	if err != nil || head <= 0 {
		// Fail closed: without a trustworthy head nothing is settled.
		if err != nil {
			log.Sugar.Warnf("[EVM-DEPTH] skip drain network=%s: head unavailable: %v", q.network, err)
		}
		return 0
	}

	depth := 1
	if q.depth != nil {
		depth = q.depth(q.network)
	}
	cutoff := confirmedBlockNumber(head, depth)

	q.mu.Lock()
	ready := make([]evmPendingCredit, 0, len(q.items))
	waiting := q.items[:0]
	for _, item := range q.items {
		if item.block <= cutoff {
			ready = append(ready, item)
			continue
		}
		waiting = append(waiting, item)
	}
	q.items = waiting
	q.mu.Unlock()

	for _, item := range ready {
		item.credit()
	}
	return len(ready)
}

// Run drains the queue on a ticker until ctx is cancelled.
func (q *evmCreditQueue) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.Drain(ctx)
		}
	}
}

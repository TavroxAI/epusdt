package task

import (
	"context"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/model/service"
	"github.com/GMWalletApp/epusdt/util/log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// evmNativeCatchUpBlocks bounds the block window rescanned for native transfers
// whenever the scanner (re)connects. Native transfers carry no logs, so a missed
// window cannot be recovered from a log query afterwards; the window therefore
// has to cover the longest plausible gap. One block costs one
// eth_getBlockByNumber with full transaction bodies, so the window stays small
// and payments still have to arrive inside the order pay window.
var evmNativeCatchUpBlocks = uint64(64)

// StartEvmNativeScanner watches native coin transfers (ETH, BNB) for one EVM
// network. ERC20 detection subscribes to Transfer logs, which native transfers
// never emit, so this scanner subscribes to newHeads and inspects the
// transactions of every block instead. It stays idle until the chain is enabled
// and a native chain_tokens row exists, so adding the row in the admin console
// is what turns it on.
func StartEvmNativeScanner(network string, logPrefix string) {
	for {
		if data.IsChainEnabled(network) {
			if token, ok := loadEvmNativeToken(network, logPrefix); ok {
				runEvmNativeListener(network, logPrefix, token)
			}
		}
		time.Sleep(10 * time.Second)
	}
}

// loadEvmNativeToken returns the enabled native coin row of the network, if the
// network has one and the operator configured it with the canonical symbol.
func loadEvmNativeToken(network, logPrefix string) (mdb.ChainToken, bool) {
	symbol, ok := service.EvmNativeSymbol(network)
	if !ok {
		return mdb.ChainToken{}, false
	}
	tokens, err := data.ListEnabledChainTokensByNetwork(network)
	if err != nil {
		log.Sugar.Errorf("%s load chain_tokens err=%v", logPrefix, err)
		return mdb.ChainToken{}, false
	}
	for _, token := range tokens {
		if service.IsEvmNativeToken(token) && strings.EqualFold(strings.TrimSpace(token.Symbol), symbol) {
			return token, true
		}
	}
	return mdb.ChainToken{}, false
}

func runEvmNativeListener(network, logPrefix string, token mdb.ChainToken) {
	ctx, cancel := chainEnabledWatchdog(network, logPrefix, chainTokenFingerprint(network))
	defer cancel()

	watched := &evmNativeWatchList{addrs: map[string]struct{}{}}
	if !watched.refresh(network, logPrefix) {
		log.Sugar.Warnf("%s no enabled wallet addresses, native scanner idle", logPrefix)
		return
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				watched.refresh(network, logPrefix)
			}
		}
	}()

	node, ok := resolveChainWsNode(network, logPrefix)
	if !ok {
		return
	}
	log.Sugar.Infof("%s connecting using WSS node %s watching %s native transfers",
		logPrefix, data.RpcNodeLogLabel(node), strings.ToUpper(strings.TrimSpace(token.Symbol)))

	runEvmNativeWsLoop(ctx, network, logPrefix, node, token, watched)
}

// evmNativeWatchList holds the receive addresses of one network. It is refreshed
// from chain wallets every 5s by runEvmNativeListener.
type evmNativeWatchList struct {
	mu    sync.RWMutex
	addrs map[string]struct{}
}

func (w *evmNativeWatchList) refresh(network, logPrefix string) bool {
	wallets, err := data.GetAvailableWalletAddressByNetwork(network)
	if err != nil {
		log.Sugar.Warnf("%s refresh wallet addresses: %v", logPrefix, err)
		return false
	}
	next := make(map[string]struct{}, len(wallets))
	for _, wallet := range wallets {
		address := strings.TrimSpace(wallet.Address)
		if !common.IsHexAddress(address) {
			continue
		}
		next[strings.ToLower(common.HexToAddress(address).Hex())] = struct{}{}
	}
	w.mu.Lock()
	w.addrs = next
	w.mu.Unlock()
	return len(next) > 0
}

func (w *evmNativeWatchList) has(address common.Address) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.addrs[strings.ToLower(address.Hex())]
	return ok
}

// runEvmNativeWsLoop owns one websocket connection: it reconnects on errors and,
// like the log listener, on a silent subscription. newHeads doubles as the
// heartbeat, so staleness means "no new block for evmWsStaleTimeout".
func runEvmNativeWsLoop(ctx context.Context, network, logPrefix string, node mdb.RpcNode, token mdb.ChainToken, watched *evmNativeWatchList) {
	const (
		minBackoff = 2 * time.Second
		maxBackoff = 60 * time.Second
		rejoinWait = 3 * time.Second
	)
	failWait := minBackoff
	for {
		if ctx.Err() != nil {
			return
		}

		dialCtx, cancelDial := context.WithTimeout(ctx, evmNodeDialTimeout)
		client, err := ethclient.DialContext(dialCtx, node.Url)
		cancelDial()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Sugar.Warnf("%s dial: %v, retry in %s", logPrefix, err, failWait)
			if recordEvmNodeFailure(logPrefix, network, node, "dial") {
				return
			}
			if !sleepOrDone(ctx, failWait) {
				return
			}
			failWait = nextBackoff(failWait, maxBackoff)
			continue
		}

		heads := make(chan *types.Header, 16)
		sub, err := client.SubscribeNewHead(ctx, heads)
		if err != nil {
			client.Close()
			if ctx.Err() != nil {
				return
			}
			log.Sugar.Warnf("%s subscribe newHeads: %v, retry in %s", logPrefix, err, failWait)
			if recordEvmNodeFailure(logPrefix, network, node, "subscribe") {
				return
			}
			if !sleepOrDone(ctx, failWait) {
				return
			}
			failWait = nextBackoff(failWait, maxBackoff)
			continue
		}
		failWait = minBackoff
		data.RecordRpcSuccess(network)
		log.Sugar.Infof("%s subscribed to newHeads using WSS node %s", logPrefix, data.RpcNodeLogLabel(node))

		lastScanned := catchUpEvmNativeBlocks(ctx, client, network, logPrefix, token, watched)
		lastProgress := time.Now()
		ticker := time.NewTicker(evmStatsIdleInterval)
		reconnect := false
		for !reconnect {
			select {
			case <-ctx.Done():
				ticker.Stop()
				sub.Unsubscribe()
				client.Close()
				return
			case head := <-heads:
				if head == nil || head.Number == nil {
					continue
				}
				lastProgress = time.Now()
				number := head.Number.Uint64()
				// Only scan blocks that have reached the configured depth. Blocks
				// near the tip are picked up by a later head, so nothing is skipped
				// and no transfer is ever settled on a block that can still be
				// reorganised away.
				target := number
				if depth := minConfirmationsFor(network); depth > 1 {
					confirmed := confirmedBlockNumber(int64(number), depth)
					if confirmed <= 0 {
						continue
					}
					target = uint64(confirmed)
				}
				if target <= lastScanned {
					continue
				}
				scanEvmNativeBlockRange(ctx, client, network, logPrefix, token, watched, lastScanned+1, target)
				lastScanned = target
			case err := <-sub.Err():
				if err != nil {
					log.Sugar.Warnf("%s newHeads subscription error: %v, reconnecting", logPrefix, err)
				} else {
					log.Sugar.Warnf("%s newHeads subscription closed, reconnecting", logPrefix)
				}
				reconnect = true
			case <-ticker.C:
				if evmWsStale(lastProgress, time.Now(), evmWsStaleTimeout) {
					log.Sugar.Warnf("%s no new block for %s, reconnecting", logPrefix, evmWsStaleTimeout)
					reconnect = true
				}
			}
		}
		ticker.Stop()
		sub.Unsubscribe()
		client.Close()
		if !sleepOrDone(ctx, rejoinWait) {
			return
		}
	}
}

// catchUpEvmNativeBlocks rescans the tail of the chain so transfers that arrived
// while the connection was down (or while the process restarted) are not lost.
func catchUpEvmNativeBlocks(ctx context.Context, client *ethclient.Client, network, logPrefix string, token mdb.ChainToken, watched *evmNativeWatchList) uint64 {
	headCtx, cancel := context.WithTimeout(ctx, evmStatsHeaderTimeout)
	latest, err := client.BlockNumber(headCtx)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			log.Sugar.Warnf("%s latest block: %v, starting from the next head", logPrefix, err)
		}
		return 0
	}
	if latest == 0 {
		return 0
	}
	from := uint64(1)
	if latest > evmNativeCatchUpBlocks {
		from = latest - evmNativeCatchUpBlocks + 1
	}
	// Same depth rule as the live loop: never scan into the unconfirmed tail.
	to := latest
	if depth := minConfirmationsFor(network); depth > 1 {
		confirmed := confirmedBlockNumber(int64(latest), depth)
		if confirmed <= 0 {
			return 0
		}
		to = uint64(confirmed)
	}
	if to < from {
		return to
	}
	log.Sugar.Infof("%s catching up native transfers in blocks %d..%d", logPrefix, from, to)
	scanEvmNativeBlockRange(ctx, client, network, logPrefix, token, watched, from, to)
	return to
}

func scanEvmNativeBlockRange(ctx context.Context, client *ethclient.Client, network, logPrefix string, token mdb.ChainToken, watched *evmNativeWatchList, from, to uint64) {
	for number := from; number <= to; number++ {
		blockCtx, cancel := context.WithTimeout(ctx, evmStatsHeaderTimeout)
		block, err := client.BlockByNumber(blockCtx, new(big.Int).SetUint64(number))
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				data.RecordRpcFailure(network)
				log.Sugar.Warnf("%s fetch block %d: %v", logPrefix, number, err)
			}
			return
		}
		data.RecordRpcSuccess(network)
		scanEvmNativeBlock(ctx, client, network, logPrefix, token, watched, block)
		if number == ^uint64(0) {
			return
		}
	}
}

// scanEvmNativeBlock dispatches every native transfer that pays a watched address
// and actually succeeded on chain.
func scanEvmNativeBlock(ctx context.Context, client evmNativeReceiptReader, network, logPrefix string, token mdb.ChainToken, watched *evmNativeWatchList, block *types.Block) {
	for _, transfer := range evmNativeTransfersInBlock(block, watched) {
		if !evmNativeTransferSucceeded(ctx, client, logPrefix, transfer) {
			continue
		}
		log.Sugar.Debugf("%s native transfer block=%d tx=%s amount=%s", logPrefix, block.NumberU64(), transfer.txHash.Hex(), transfer.value.String())
		service.TryProcessEvmNativeTransfer(network, transfer.to, transfer.value, transfer.txHash.Hex(), transfer.blockTsMs, token)
	}
}

// evmNativeTransfer is one native coin payment found in a block.
type evmNativeTransfer struct {
	to        common.Address
	value     *big.Int
	txHash    common.Hash
	blockTsMs int64
}

// evmNativeTransfersInBlock returns the native transfers of the block that pay a
// watched address. Contract creation transactions have no recipient, so they are
// skipped here; the receipt status is checked separately by the caller.
func evmNativeTransfersInBlock(block *types.Block, watched *evmNativeWatchList) []evmNativeTransfer {
	if block == nil {
		return nil
	}
	var transfers []evmNativeTransfer
	blockTsMs := int64(block.Time()) * 1000
	for _, tx := range block.Transactions() {
		to := tx.To()
		if to == nil || !watched.has(*to) {
			continue
		}
		value := tx.Value()
		if value == nil || value.Sign() <= 0 {
			continue
		}
		transfers = append(transfers, evmNativeTransfer{to: *to, value: value, txHash: tx.Hash(), blockTsMs: blockTsMs})
	}
	return transfers
}

// evmNativeReceiptReader is the only chain call the native scanner needs beyond
// block bodies.
type evmNativeReceiptReader interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
}

// evmNativeTransferSucceeded reports whether the transfer was actually executed.
// A value transfer can fail — for example when the gas limit cannot cover the
// 25,000 surcharge for crediting a previously empty account — and a failed
// transfer must never settle an order.
func evmNativeTransferSucceeded(ctx context.Context, client evmNativeReceiptReader, logPrefix string, transfer evmNativeTransfer) bool {
	receiptCtx, cancel := context.WithTimeout(ctx, evmStatsHeaderTimeout)
	defer cancel()
	receipt, err := client.TransactionReceipt(receiptCtx, transfer.txHash)
	if err != nil {
		log.Sugar.Warnf("%s receipt for native transfer %s: %v", logPrefix, transfer.txHash.Hex(), err)
		return false
	}
	if receipt == nil || receipt.Status != types.ReceiptStatusSuccessful {
		status := uint64(0)
		if receipt != nil {
			status = receipt.Status
		}
		log.Sugar.Warnf("%s skip failed native transfer tx=%s status=%d", logPrefix, transfer.txHash.Hex(), status)
		return false
	}
	return true
}

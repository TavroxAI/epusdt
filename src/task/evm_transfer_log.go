package task

import (
	"context"
	"errors"
	"math/big"
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

var errNoEvmHeadSource = errors.New("no live evm head source")

// evmHeadSources holds, per network, the head source backed by the listener's
// current websocket client. It is a registry rather than a captured pointer
// because the listener reconnects: the queue must always ask the live connection,
// and fail closed while there is none.
var evmHeadSources sync.Map // network -> func(context.Context) (int64, error)

func setEvmHeadSource(network string, fn func(context.Context) (int64, error)) {
	if fn == nil {
		evmHeadSources.Delete(network)
		return
	}
	evmHeadSources.Store(network, fn)
}

func evmHeadSource(network string) func(context.Context) (int64, error) {
	value, ok := evmHeadSources.Load(network)
	if !ok {
		return nil
	}
	fn, _ := value.(func(context.Context) (int64, error))
	return fn
}

var (
	evmQueuesMu sync.Mutex
	evmQueues   = make(map[string]*evmCreditQueue)
)

// evmCreditQueueFor returns the process-wide depth queue for a network.
func evmCreditQueueFor(network string) *evmCreditQueue {
	evmQueuesMu.Lock()
	defer evmQueuesMu.Unlock()

	if queue, ok := evmQueues[network]; ok {
		return queue
	}
	queue := newEvmCreditQueue(network, func(ctx context.Context) (int64, error) {
		source := evmHeadSource(network)
		if source == nil {
			return 0, errNoEvmHeadSource
		}
		return source(ctx)
	})
	evmQueues[network] = queue
	return queue
}

// startEvmCreditDrainers keeps the depth queues moving. One goroutine per EVM
// network; the queues themselves are created on first use.
func startEvmCreditDrainers() {
	for _, network := range []string{
		mdb.NetworkEthereum,
		mdb.NetworkBsc,
		mdb.NetworkPolygon,
		mdb.NetworkPlasma,
	} {
		go evmCreditQueueFor(network).Run(context.Background(), 2*time.Second)
	}
}

// evmBlockTimestampMs reads the block timestamp for the on-chain order time,
// falling back to local time when the node cannot answer (the timestamp is
// informational; the transfer itself is still checked).
func evmBlockTimestampMs(client *ethclient.Client, network, logPrefix string, blockNumber uint64) int64 {
	header, err := client.HeaderByNumber(context.Background(), new(big.Int).SetUint64(blockNumber))
	if err != nil {
		data.RecordRpcFailure(network)
		log.Sugar.Warnf("%s HeaderByNumber block=%d: %v, using local time", logPrefix, blockNumber, err)
		return time.Now().UnixMilli()
	}
	data.RecordRpcSuccess(network)
	if header == nil || header.Time == 0 {
		return time.Now().UnixMilli()
	}
	return int64(header.Time) * 1000
}

// evmClientHead asks the live websocket client for its current head.
func evmClientHead(client *ethclient.Client, network, logPrefix string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), evmStatsHeaderTimeout)
	defer cancel()

	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		data.RecordRpcFailure(network)
		log.Sugar.Warnf("%s head lookup failed: %v", logPrefix, err)
		return 0, err
	}
	data.RecordRpcSuccess(network)
	if header == nil || header.Number == nil || !header.Number.IsInt64() {
		return 0, errors.New("head unavailable")
	}
	return header.Number.Int64(), nil
}

// creditConfirmedEvmERC20Transfer is the single entry point the websocket
// listeners use for an ERC-20 Transfer log. It settles the transfer immediately
// when the block is already deep enough, and queues it otherwise; a log the chain
// has already removed is never settled at all.
func creditConfirmedEvmERC20Transfer(client *ethclient.Client, network, logPrefix string, vLog types.Log, isWatched func(common.Address) bool) {
	if len(vLog.Topics) < 3 {
		return
	}
	if vLog.Topics[0].String() != transferEventHash.String() {
		return
	}
	if vLog.Removed {
		log.Sugar.Warnf("%s ignoring removed Transfer log block=%d tx=%s (chain reorg)",
			logPrefix, vLog.BlockNumber, vLog.TxHash.Hex())
		return
	}

	toAddr := common.HexToAddress(vLog.Topics[2].Hex())
	if isWatched != nil && !isWatched(toAddr) {
		return
	}

	blockTsMs := evmBlockTimestampMs(client, network, logPrefix, vLog.BlockNumber)
	amount := new(big.Int).SetBytes(vLog.Data)
	contract := vLog.Address
	txHash := vLog.TxHash.Hex()
	credit := func() {
		service.TryProcessEvmERC20Transfer(network, contract, toAddr, amount, txHash, blockTsMs)
	}

	blockNumber := int64(vLog.BlockNumber)
	depth := minConfirmationsFor(network)
	head, err := evmClientHead(client, network, logPrefix)
	if err != nil {
		evmCreditQueueFor(network).Offer(blockNumber, credit)
		return
	}
	if transferConfirmed(blockNumber, head, depth) {
		credit()
		return
	}
	log.Sugar.Debugf("%s transfer block=%d head=%d depth=%d not confirmed yet, queued", logPrefix, blockNumber, head, depth)
	evmCreditQueueFor(network).Offer(blockNumber, credit)
}

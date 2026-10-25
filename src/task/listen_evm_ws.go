package task

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/util/log"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

const evmStatsHeaderTimeout = 10 * time.Second

var (
	// evmStatsIdleInterval is how long the listener waits with no activity before
	// asking the node for its latest header. It doubles as the heartbeat probe.
	evmStatsIdleInterval = 30 * time.Second

	// evmWsStaleTimeout is how long a subscription may make no chain progress
	// (no new block header AND no transfer log) before it is considered dead.
	// Public websocket endpoints regularly stop pushing while the socket stays
	// open, and the subscription error channel never fires in that case, so
	// without this probe a chain silently stops detecting payments until the
	// process is restarted. EVM blocks arrive within seconds, so three minutes
	// without any new block is unambiguous.
	evmWsStaleTimeout = 3 * time.Minute

	// evmWsStaleMaxConsecutive is how many consecutive stalls are tolerated
	// before the node is reported as failed (and a failover is attempted). A
	// single stall is usually a transient endpoint hiccup; a node that keeps
	// stalling is not usable and should not keep the only slot forever.
	evmWsStaleMaxConsecutive = 3
)

// errEvmWsStale marks a reconnect that was triggered by the heartbeat probe
// rather than by a visible connection error. Callers must not count it as a
// node failure on the first occurrence.
var errEvmWsStale = errors.New("evm websocket stalled")

// runEvmWsLogListener connects to node.Url, subscribes to Transfer logs,
// and dispatches each log to handleLog. It retries on transient errors
// with exponential backoff until the node reaches the failure threshold.
// The ctx lets the caller trigger a clean exit — e.g. when admin disables
// the chain, the caller cancels the context and the function returns.
func runEvmWsLogListener(ctx context.Context, network string, logPrefix string, node mdb.RpcNode, query ethereum.FilterQuery, handleLog func(*ethclient.Client, types.Log)) {
	const (
		minBackoff       = 2 * time.Second
		maxBackoff       = 60 * time.Second
		rejoinWait       = 3 * time.Second
		stableResetAfter = 60 * time.Second
	)
	failWait := minBackoff
	wsURL := node.Url
	nodeLabel := data.RpcNodeLogLabel(node)
	consecutiveStalls := 0

	for {
		if ctx.Err() != nil {
			return
		}

		dialCtx, cancelDial := context.WithTimeout(ctx, evmNodeDialTimeout)
		client, err := ethclient.DialContext(dialCtx, wsURL)
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

		logsCh := make(chan types.Log)
		sub, err := client.SubscribeFilterLogs(ctx, query, logsCh)
		if err != nil {
			client.Close()
			if ctx.Err() != nil {
				return
			}
			log.Sugar.Warnf("%s subscribe: %v, retry in %s", logPrefix, err, failWait)
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

		log.Sugar.Infof("%s connected, subscribed to Transfer logs using WSS node %s", logPrefix, nodeLabel)

		connectedAt := time.Now()
		recvErr := recvLoop(ctx, client, sub, logsCh, network, logPrefix, handleLog)

		if ctx.Err() != nil {
			return
		}
		if errors.Is(recvErr, errEvmWsStale) {
			// A stalled subscription is not a connection error: the socket is still
			// open and may simply resume. Only a node that keeps stalling is treated
			// as failed, so a transient hiccup does not burn the failover slot.
			consecutiveStalls++
			log.Sugar.Warnf("%s subscription made no chain progress for %s, reconnecting (stall %d/%d), node=%s",
				logPrefix, evmWsStaleTimeout, consecutiveStalls, evmWsStaleMaxConsecutive, nodeLabel)
			if consecutiveStalls >= evmWsStaleMaxConsecutive {
				consecutiveStalls = 0
				if recordEvmNodeFailure(logPrefix, network, node, "stalled") {
					return
				}
			}
			if !sleepOrDone(ctx, rejoinWait) {
				return
			}
			continue
		}
		consecutiveStalls = 0
		if time.Since(connectedAt) >= stableResetAfter {
			if recvErr != nil {
				data.RecordRpcFailure(network)
			}
			data.RecordRpcNodeSuccess(node.ID)
		} else if recvErr != nil && recordEvmNodeFailure(logPrefix, network, node, recvErr.Error()) {
			return
		}
		if !sleepOrDone(ctx, rejoinWait) {
			return
		}
	}
}

func recvLoop(ctx context.Context, client *ethclient.Client, sub ethereum.Subscription, logsCh <-chan types.Log, network string, logPrefix string, handleLog func(*ethclient.Client, types.Log)) error {
	statsCtx, cancelStats := context.WithCancel(ctx)
	statsTicker := time.NewTicker(evmStatsIdleInterval)
	headerStatsDone := make(chan evmHeaderProgress, 1)
	lastStatsUpdateAt := time.Now()
	lastProgressAt := time.Now()
	lastBlockNumber := int64(0)
	headerStatsInFlight := false
	requestLatestHeader := func() {
		if headerStatsInFlight {
			return
		}
		headerStatsInFlight = true
		go func() {
			headerStatsDone <- recordEvmLatestHeader(statsCtx, network, logPrefix, client)
		}()
	}

	defer func() {
		cancelStats()
		statsTicker.Stop()
		sub.Unsubscribe()
		client.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			log.Sugar.Infof("%s context cancelled, stopping", logPrefix)
			return nil
		case <-statsTicker.C:
			now := time.Now()
			if evmWsStale(lastProgressAt, now, evmWsStaleTimeout) {
				return errEvmWsStale
			}
			if shouldRefreshEvmLatestHeader(lastStatsUpdateAt, headerStatsInFlight, now) {
				requestLatestHeader()
			}
		case progress := <-headerStatsDone:
			headerStatsInFlight = false
			if progress.ok {
				lastStatsUpdateAt = time.Now()
				// Only a *new* block counts as progress: an endpoint that answers
				// with the same height over and over is not delivering the chain.
				if progress.number > lastBlockNumber {
					lastBlockNumber = progress.number
					lastProgressAt = time.Now()
				}
			}
		case err := <-sub.Err():
			if err != nil {
				log.Sugar.Warnf("%s subscription error: %v, reconnecting", logPrefix, err)
				return fmt.Errorf("subscription error")
			} else {
				log.Sugar.Warnf("%s subscription closed, reconnecting", logPrefix)
				return fmt.Errorf("subscription closed")
			}
		case vLog, ok := <-logsCh:
			if !ok {
				log.Sugar.Warnf("%s log channel closed, reconnecting", logPrefix)
				return fmt.Errorf("log channel closed")
			}
			if recordEvmLogBlockHeight(network, logPrefix, vLog.BlockNumber) {
				lastStatsUpdateAt = time.Now()
			}
			if vLog.BlockNumber > 0 {
				lastProgressAt = time.Now()
			}
			handleLog(client, vLog)
		}
	}
}

// evmHeaderProgress is the result of one heartbeat probe.
type evmHeaderProgress struct {
	number int64
	ok     bool
}

// evmWsStale reports whether a subscription has been silent for too long.
func evmWsStale(lastProgressAt, now time.Time, timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	return now.Sub(lastProgressAt) >= timeout
}

func shouldRefreshEvmLatestHeader(lastStatsUpdateAt time.Time, inFlight bool, now time.Time) bool {
	return !inFlight && now.Sub(lastStatsUpdateAt) >= evmStatsIdleInterval
}

func recordEvmLogBlockHeight(network string, logPrefix string, blockNumber uint64) bool {
	if blockNumber == 0 {
		return false
	}
	if blockNumber > uint64(1<<63-1) {
		log.Sugar.Warnf("%s log block number exceeds int64 range: %d", logPrefix, blockNumber)
		return false
	}
	data.RecordRpcBlockHeight(network, int64(blockNumber))
	return true
}

func recordEvmLatestHeader(ctx context.Context, network string, logPrefix string, client *ethclient.Client) evmHeaderProgress {
	headerCtx, cancel := context.WithTimeout(ctx, evmStatsHeaderTimeout)
	defer cancel()

	header, err := client.HeaderByNumber(headerCtx, nil)
	if err != nil {
		if ctx.Err() != nil {
			return evmHeaderProgress{}
		}
		data.RecordRpcFailure(network)
		log.Sugar.Warnf("%s latest header stats failed: %v", logPrefix, err)
		return evmHeaderProgress{}
	}
	data.RecordRpcSuccess(network)
	if !recordEvmHeaderBlockHeight(network, logPrefix, header) {
		return evmHeaderProgress{}
	}
	return evmHeaderProgress{number: header.Number.Int64(), ok: true}
}

func recordEvmHeaderBlockHeight(network string, logPrefix string, header *types.Header) bool {
	if header == nil || header.Number == nil {
		return false
	}
	if !header.Number.IsInt64() {
		log.Sugar.Warnf("%s latest header block number exceeds int64 range: %s", logPrefix, header.Number.String())
		return false
	}
	data.RecordRpcBlockHeight(network, header.Number.Int64())
	return true
}

func recordEvmNodeFailure(logPrefix string, network string, node mdb.RpcNode, reason string) bool {
	data.RecordRpcFailure(network)
	failures, cooling := data.RecordRpcNodeFailure(node.ID)
	nodeLabel := data.RpcNodeLogLabel(node)
	if !cooling {
		log.Sugar.Warnf("%s node failed (%s), node=%s failures=%d/%d", logPrefix, reason, nodeLabel, failures, data.RpcFailoverThreshold)
		return false
	}
	log.Sugar.Warnf("%s node reached fail threshold (%s), node=%s, resolving another node", logPrefix, reason, nodeLabel)
	return true
}

// sleepOrDone waits for d or for ctx cancellation, whichever comes
// first. Returns true if the sleep completed normally, false if ctx
// was cancelled (caller should exit).
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	n := cur * 2
	if n > max {
		return max
	}
	return n
}

package task

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GMWalletApp/epusdt/model/mdb"
	appLog "github.com/GMWalletApp/epusdt/util/log"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestEvmWsStale(t *testing.T) {
	base := time.Now()
	testCases := []struct {
		name     string
		last     time.Time
		now      time.Time
		timeout  time.Duration
		expected bool
	}{
		{"just progressed", base, base.Add(10 * time.Second), 3 * time.Minute, false},
		{"inside the window", base, base.Add(2 * time.Minute), 3 * time.Minute, false},
		{"exactly at the timeout", base, base.Add(3 * time.Minute), 3 * time.Minute, true},
		{"past the timeout", base, base.Add(5 * time.Minute), 3 * time.Minute, true},
		{"probe disabled", base, base.Add(time.Hour), 0, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := evmWsStale(testCase.last, testCase.now, testCase.timeout); got != testCase.expected {
				t.Fatalf("evmWsStale(%s, %s, %s) = %v, want %v", testCase.last, testCase.now, testCase.timeout, got, testCase.expected)
			}
		})
	}
}

// TestEvmWsReconnectsWhenSubscriptionGoesSilent covers the failure mode seen in
// production: a public websocket endpoint keeps the socket open, never reports a
// subscription error, and simply stops delivering logs. Without the heartbeat
// probe the chain would stop detecting payments until the process restarts.
func TestEvmWsReconnectsWhenSubscriptionGoesSilent(t *testing.T) {
	node := &fakeEvmWsNode{pushLogs: false, answerHeaders: false}
	startEvmWsListener(t, node)

	deadline := time.Now().Add(10 * time.Second)
	for node.connections.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := node.connections.Load(); got < 2 {
		t.Fatalf("silent subscription was not replaced: connections=%d, want >= 2", got)
	}
}

// TestEvmWsStaysConnectedWhileLogsArrive is the negative control: as long as the
// endpoint keeps delivering logs (or advancing the head), the listener must not
// reconnect.
func TestEvmWsStaysConnectedWhileLogsArrive(t *testing.T) {
	node := &fakeEvmWsNode{pushLogs: true, answerHeaders: true}
	startEvmWsListener(t, node)

	time.Sleep(1500 * time.Millisecond)
	if got := node.connections.Load(); got != 1 {
		t.Fatalf("healthy subscription was dropped: connections=%d, want 1", got)
	}
}

// TestWarnMissingHttpNodeIsActionableAndRateLimited pins two properties of the
// missing-backfill warning: it explains the consequence and the fix, and it is
// not repeated on every retry-loop iteration.
func TestWarnMissingHttpNodeIsActionableAndRateLimited(t *testing.T) {
	previousSugar := appLog.Sugar
	core, observed := observer.New(zapcore.DebugLevel)
	appLog.Sugar = zap.New(core).Sugar()
	missingHttpNodeWarnMu.Lock()
	previousWarns := missingHttpNodeWarnAt
	missingHttpNodeWarnAt = make(map[string]time.Time)
	missingHttpNodeWarnMu.Unlock()
	t.Cleanup(func() {
		appLog.Sugar = previousSugar
		missingHttpNodeWarnMu.Lock()
		missingHttpNodeWarnAt = previousWarns
		missingHttpNodeWarnMu.Unlock()
	})

	warnMissingHttpNode(mdb.NetworkEthereum, "[TEST-BACKFILL]")
	warnMissingHttpNode(mdb.NetworkEthereum, "[TEST-BACKFILL]")

	entries := observed.FilterMessageSnippet("backfill scanner stays idle").All()
	if len(entries) != 1 {
		t.Fatalf("warning was logged %d times, want exactly 1 within the dedupe window", len(entries))
	}
	if !strings.Contains(entries[0].Message, "purpose=general") {
		t.Fatalf("warning does not tell the operator how to fix it: %q", entries[0].Message)
	}
}

// fakeEvmWsNode speaks just enough JSON-RPC over websocket for
// ethclient.SubscribeFilterLogs plus the listener's header probe, so a test can
// choose between "keeps making progress" and "silent but connected".
type fakeEvmWsNode struct {
	pushLogs      bool
	answerHeaders bool
	connections   atomic.Int32
	block         atomic.Uint64
	mu            sync.Mutex
}

func (f *fakeEvmWsNode) handle() http.HandlerFunc {
	upgrader := websocket.Upgrader{}
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		f.connections.Add(1)

		subscribed := make(chan struct{}, 1)
		if f.pushLogs {
			go f.pushTransferLogs(conn, subscribed)
		}

		writeResult := func(id json.RawMessage, result any) {
			payload, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
			if err != nil {
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			_ = conn.WriteMessage(websocket.TextMessage, payload)
		}

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var request struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if err := json.Unmarshal(message, &request); err != nil {
				continue
			}
			switch request.Method {
			case "eth_subscribe":
				writeResult(request.ID, "0x1")
				select {
				case subscribed <- struct{}{}:
				default:
				}
			case "eth_getBlockByNumber":
				if !f.answerHeaders {
					continue
				}
				writeResult(request.ID, fakeHeader(f.block.Add(1)))
			default:
				writeResult(request.ID, nil)
			}
		}
	}
}

func (f *fakeEvmWsNode) pushTransferLogs(conn *websocket.Conn, subscribed <-chan struct{}) {
	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		return
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		payload, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"method":  "eth_subscription",
			"params": map[string]any{
				"subscription": "0x1",
				"result": map[string]any{
					"address":          "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238",
					"topics":           []string{"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"},
					"data":             "0x00000000000000000000000000000000000000000000000000000000000f4240",
					"blockNumber":      fmt.Sprintf("0x%x", f.block.Add(1)),
					"transactionHash":  "0x0000000000000000000000000000000000000000000000000000000000000002",
					"transactionIndex": "0x0",
					"blockHash":        "0x0000000000000000000000000000000000000000000000000000000000000003",
					"logIndex":         "0x0",
					"removed":          false,
				},
			},
		})
		if err != nil {
			return
		}
		f.mu.Lock()
		err = conn.WriteMessage(websocket.TextMessage, payload)
		f.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func fakeHeader(number uint64) map[string]any {
	return map[string]any{
		"number":           fmt.Sprintf("0x%x", number),
		"hash":             "0x0000000000000000000000000000000000000000000000000000000000000001",
		"parentHash":       "0x0000000000000000000000000000000000000000000000000000000000000000",
		"nonce":            "0x0000000000000000",
		"sha3Uncles":       "0x0000000000000000000000000000000000000000000000000000000000000000",
		"logsBloom":        "0x",
		"transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
		"stateRoot":        "0x0000000000000000000000000000000000000000000000000000000000000000",
		"receiptsRoot":     "0x0000000000000000000000000000000000000000000000000000000000000000",
		"miner":            "0x0000000000000000000000000000000000000000",
		"difficulty":       "0x0",
		"totalDifficulty":  "0x0",
		"extraData":        "0x",
		"size":             "0x0",
		"gasLimit":         "0x1c9c380",
		"gasUsed":          "0x0",
		"timestamp":        "0x1",
		"uncles":           []string{},
	}
}

// startEvmWsListener runs the listener against the fake node with a compressed
// heartbeat so the tests finish quickly. It registers cleanup for both the
// goroutine and the package level timing vars.
func startEvmWsListener(t *testing.T, node *fakeEvmWsNode) {
	t.Helper()

	previousSugar := appLog.Sugar
	appLog.Sugar = zap.NewNop().Sugar()
	previousIdle, previousStale := evmStatsIdleInterval, evmWsStaleTimeout
	evmStatsIdleInterval = 40 * time.Millisecond
	evmWsStaleTimeout = 250 * time.Millisecond

	server := httptest.NewServer(node.handle())
	wsURL := "ws" + server.URL[len("http"):]

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runEvmWsLogListener(ctx, mdb.NetworkEthereum, "[TEST-WS]",
			mdb.RpcNode{BaseModel: mdb.BaseModel{ID: 1}, Url: wsURL},
			ethereum.FilterQuery{},
			func(*ethclient.Client, types.Log) {},
		)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("listener did not stop after cancel")
		}
		server.Close()
		appLog.Sugar = previousSugar
		evmStatsIdleInterval = previousIdle
		evmWsStaleTimeout = previousStale
	})
}

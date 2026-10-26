package task

import (
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/util/log"
	"github.com/robfig/cron/v3"
)

func Start() {
	log.Sugar.Info("[task] Starting task scheduler...")
	// The ETH listener short-circuits internally when chain is disabled
	// or no tokens are configured, so always launch the goroutine.
	go StartEthereumWebSocketListener()
	go StartBscWebSocketListener()
	go StartPolygonWebSocketListener()
	go StartPlasmaWebSocketListener()
	// Native coins emit no logs, so they need their own block scanner. It stays
	// idle until a native chain_tokens row (ethereum/ETH, binance/BNB) is enabled.
	go StartEvmNativeScanner(mdb.NetworkEthereum, "[ETH-NATIVE]")
	go StartEvmNativeScanner(mdb.NetworkBsc, "[BNB-NATIVE]")

	go StartEthereumBackfillScannerListener()
	go StartBscBackfillScannerListener()
	go StartPolygonBackfillScannerListener()
	go StartPlasmaBackfillScannerListener()
	go StartTronBlockScannerListener()
	go StartTonBlockScannerListener()
	go StartAptosLedgerScannerListener()

	// Observed EVM transfers wait here until their block reaches the configured
	// settlement depth, so a transfer that a reorg removes never becomes a paid
	// order with a delivered callback.
	startEvmCreditDrainers()

	c := cron.New()

	// Solana polling
	_, err := c.AddJob("@every 5s", ListenSolJob{})
	if err != nil {
		log.Sugar.Errorf("[task] Failed to add ListenSolJob: %v", err)
		return
	}

	log.Sugar.Info("[task] ListenSolJob scheduled successfully (@every 5s)")

	// RPC node health checks
	_, err = c.AddJob("@every 30s", RpcHealthJob{})
	if err != nil {
		log.Sugar.Errorf("[task] Failed to add RpcHealthJob: %v", err)
		return
	}
	log.Sugar.Info("[task] RpcHealthJob scheduled successfully (@every 30s)")

	c.Start()
	log.Sugar.Info("[task] Task scheduler started")
}

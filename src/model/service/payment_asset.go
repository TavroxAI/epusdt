package service

import (
	"strings"

	"github.com/GMWalletApp/epusdt/model/mdb"
)

func ChainTokenReadyForPayment(token mdb.ChainToken) bool {
	if strings.TrimSpace(token.Symbol) == "" {
		return false
	}
	if chainTokenRequiresAssetID(token) && strings.TrimSpace(token.ContractAddress) == "" {
		return false
	}
	return true
}

// EvmNativeSymbol returns the canonical native coin symbol of an EVM network.
// Native transfers carry no logs, so they are scanned from block transactions
// instead; only the symbol returned here may be configured without a contract
// address on that network.
func EvmNativeSymbol(network string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case mdb.NetworkEthereum:
		return "ETH", true
	case mdb.NetworkBsc:
		return "BNB", true
	}
	return "", false
}

// IsEvmNativeToken reports whether the row describes the native coin of an EVM
// network (empty contract address plus that chain's canonical symbol).
func IsEvmNativeToken(token mdb.ChainToken) bool {
	if strings.TrimSpace(token.ContractAddress) != "" {
		return false
	}
	symbol, ok := EvmNativeSymbol(token.Network)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(token.Symbol), symbol)
}

func chainTokenRequiresAssetID(token mdb.ChainToken) bool {
	network := strings.ToLower(strings.TrimSpace(token.Network))
	symbol := strings.ToUpper(strings.TrimSpace(token.Symbol))
	switch network {
	case mdb.NetworkTron:
		return symbol != "TRX"
	case mdb.NetworkSolana:
		return symbol != "SOL"
	case mdb.NetworkTon:
		return symbol != TonNativeSymbol
	default:
		return !IsEvmNativeToken(token)
	}
}

package wallet

import (
	"errors"
	"mcw/aptos"
	"mcw/btc"
	"mcw/eth"
	"mcw/sol"
	"mcw/types"
)

var (
	ethereum = eth.Ethereum{}
	solana = sol.Solana{}
	bitcoin = btc.Bitcoin{}
	aptosI = aptos.Aptos{}
)
var ErrUnsupportedNetwork = errors.New("network not supported, please pass in network")

func WalletFromMnemonic(wp types.WalletParam) (types.Wallet, error) {
	switch wp.Network {
		case "eth", "ethereum":
        	return ethereum.WalletFromMnemonic(wp)
    	case "sol", "solana":
       		return solana.WalletFromMnemonic(wp)
    	case "apt", "aptos":
        	return aptosI.WalletFromMnemonic(wp)
		case "btc", "bitcoin":
        	return bitcoin.WalletFromMnemonic(wp)
		default:
			return types.Wallet{}, ErrUnsupportedNetwork 
	}
}

func CreateWallet(cwp types.CWParam) (types.Wallet, error) {
	switch cwp.Network {
		case "eth", "ethereum":
        	return ethereum.CreateWallet(cwp)
    	case "sol", "solana":
       		return solana.CreateWallet(cwp)
    	case "apt", "aptos":
        	return aptosI.CreateWallet(cwp)
		case "btc", "bitcoin":
        	return bitcoin.CreateWallet(cwp)
		default:
			return types.Wallet{}, ErrUnsupportedNetwork 
	}
}

func GetAddressFromPrivateKey(network string, privateKey string) (types.Address, error) {
	switch network {
		case "eth", "ethereum":
        	return ethereum.GetAddressFromPrivateKey(privateKey)
    	case "sol", "solana":
       		return solana.GetAddressFromPrivateKey(privateKey)
    	case "apt", "aptos":
        	return aptosI.GetAddressFromPrivateKey(privateKey)
		case "btc", "bitcoin":
        	return bitcoin.GetAddressFromPrivateKey(privateKey)
		default:
			return types.Address{}, ErrUnsupportedNetwork 
	}
}

func GetBalance(bp types.BalanceParam) (types.Balance, error) {
	switch bp.Network {
		case "eth", "ethereum":
        	return ethereum.GetBalance(bp)
    	case "sol", "solana":
       		return solana.GetBalance(bp)
    	case "apt", "aptos":
        	return aptosI.GetBalance(bp)
		case "btc", "bitcoin":
        	return bitcoin.GetBalance(bp)
		default:
			return types.Balance{}, ErrUnsupportedNetwork 
	}
}

func GetTokenBalance(tbp types.TBParam) (types.TokenBalance, error) {
	switch tbp.Network {
		case "eth", "ethereum":
        	return ethereum.GetTokenBalance(tbp)
    	case "sol", "solana":
       		return solana.GetTokenBalance(tbp)
    	case "apt", "aptos":
        	return aptosI.GetTokenBalance(tbp)
		case "btc", "bitcoin":
        	return bitcoin.GetTokenBalance(tbp)
		default:
			return types.TokenBalance{}, ErrUnsupportedNetwork 
	}
}

func GetTxByHash(hp types.HashParam) (types.TransactionByHash, error) {
		switch hp.Network {
		case "eth", "ethereum":
        	return ethereum.GetTxByHash(hp)
    	case "sol", "solana":
       		return solana.GetTxByHash(hp)
    	case "apt", "aptos":
        	return aptosI.GetTxByHash(hp)
		case "btc", "bitcoin":
        	return bitcoin.GetTxByHash(hp)
		default:
			return types.TransactionByHash{}, ErrUnsupportedNetwork 
	}
}

func Transfer(tp types.TransferParam) (types.TransferData, error) {
	switch tp.Network {
		case "eth", "ethereum":
        	return ethereum.Transfer(tp)
    	case "sol", "solana":
       		return solana.Transfer(tp)
    	case "apt", "aptos":
        	return aptosI.Transfer(tp)
		case "btc", "bitcoin":
        	return bitcoin.Transfer(tp)
		default:
			return types.TransferData{}, ErrUnsupportedNetwork 
	}
}

func TransferToken(ttp types.TransferTokenParam) (types.TransferData, error) {
	switch ttp.Network {
		case "eth", "ethereum":
        	return ethereum.TransferToken(ttp)
    	case "sol", "solana":
       		return solana.TransferToken(ttp)
    	case "apt", "aptos":
        	return aptosI.TransferToken(ttp)
		case "btc", "bitcoin":
        	return bitcoin.TransferToken(ttp)
		default:
			return types.TransferData{}, ErrUnsupportedNetwork 
	}
}

func GetTokenInfo(tip types.TokenInfoParam) (types.TokenInfo, error) {
	switch tip.Network {
		case "eth", "ethereum":
        	return ethereum.GetTokenInfo(tip)
    	case "sol", "solana":
       		return solana.GetTokenInfo(tip)
    	case "apt", "aptos":
        	return aptosI.GetTokenInfo(tip)
		case "btc", "bitcoin":
        	return bitcoin.GetTokenInfo(tip)
		default:
			return types.TokenInfo{}, ErrUnsupportedNetwork 
	}
}

func SmartContractCall(payload types.SmartContractCallPayload) (interface{}, error) {
	switch payload.Network {
		case "eth", "ethereum":
        	return ethereum.SmartContractCall(payload)
    	case "sol", "solana":
       		return solana.SmartContractCall(payload)
    	case "apt", "aptos":
        	return aptosI.SmartContractCall(payload)
		case "btc", "bitcoin":
        	return bitcoin.SmartContractCall(payload)
		default:
			return types.TransactionByHash{}, ErrUnsupportedNetwork 
	}
}
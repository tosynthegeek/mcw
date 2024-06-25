package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/tosynthegeek/mcw/flow"

	"github.com/tosynthegeek/mcw/aptos"
	"github.com/tosynthegeek/mcw/btc"
	"github.com/tosynthegeek/mcw/eth"
	"github.com/tosynthegeek/mcw/sol"
	"github.com/tosynthegeek/mcw/types"

	Flow "github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/onflow/flow-go-sdk/templates"
	"github.com/tyler-smith/go-bip39"
)

var (
	ethereum = eth.Ethereum{}
	solana = sol.Solana{}
	bitcoin = btc.Bitcoin{}
	aptosI = aptos.Aptos{}
	flowI = flow.Flow{}
)
var ErrUnsupportedNetwork = errors.New("unsupported network: the specified network is not recognized. Please ensure that the network name is correct and supported by the application.")

func GenerateMnemonic(bitsize int) (string, error) {
	// Validate bit size
	switch bitsize {
	case 128, 160, 192, 224, 256:
		// Valid bit sizes
	default:
		return "", fmt.Errorf("invalid bitsize: %d; must be 128, 160, 192, 224, or 256", bitsize)
	}

	entropy, err:= bip39.NewEntropy(bitsize) // 12 words
    if err != nil {
        return "", fmt.Errorf("error generating entropy: %w", err)
    }
    mnemonic, err:= bip39.NewMnemonic(entropy)
    if err != nil {
        return " ", fmt.Errorf("error creating mnemonic: %w", err)
    }

	return mnemonic, nil
}

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
		case "flow":
        	return flowI.WalletFromMnemonic(wp)
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
		case "flow":
        	return flowI.CreateWallet(cwp)
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
		case "flow":
        	return flowI.GetAddressFromPrivateKey(privateKey)
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
		case "flow":
        	return flowI.GetBalance(bp)
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
		case "flow":
        	return flowI.GetTokenBalance(tbp)
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
		case "flow":
        	return flowI.GetTxByHash(hp)
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
		case "flow":
        	return flowI.Transfer(tp)
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
		case "flow":
        	return flowI.TransferToken(ttp)
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
		case "flow":
        	return flowI.GetTokenInfo(tip)
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
		case "flow":
        	return flowI.SmartContractCall(payload)
		default:
			return types.TransactionByHash{}, ErrUnsupportedNetwork 
	}
}

/* 
CreateAccountCreationTx prepares a transaction to create a new Flow account
and calculates the expected address for this account.

Parameters:
  - wallet: The Flow wallet containing the public key for the new account.
  - payer: The address of the account that will pay for the account creation.
  - network: The Flow network (e.g., Mainnet, Testnet) where the account will be created.

Returns:
  - A pointer to the prepared transaction (*flow.Transaction).
  - The expected address of the new account (flow.Address).
  - An error if the transaction preparation or address calculation fails.

Note: This function only prepares the transaction and calculates the expected address.
The transaction still needs to be signed and submitted to the blockchain to actually
create the account. The actual address may differ if other accounts are created
before this transaction is executed. */ 
func CreateAccountCreationTx(wallet types.Wallet, payer Flow.Address, network Flow.ChainID)  (*Flow.Transaction, Flow.Address, error){
	publicKeyBytes, err := hex.DecodeString(wallet.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}
	pubKey, err:= crypto.DecodePublicKey(crypto.ECDSA_P256, publicKeyBytes)
	if err != nil {
		log.Fatal(err.Error())
	}
	accountCreationTx, err := templates.CreateAccount([]*Flow.AccountKey{
        &Flow.AccountKey{
            PublicKey: pubKey,
            SigAlgo:   crypto.ECDSA_P256,
            HashAlgo:  crypto.SHA3_256,
            Weight:    Flow.AccountKeyWeightThreshold,
        },
    }, nil, payer)
    
    if err != nil {
        return nil, Flow.EmptyAddress, fmt.Errorf("failed to create account creation transaction: %w", err)
    }

    // Calculate the expected address of the new account
    expectedAddress := Flow.NewAddressGenerator(network).NextAddress()
    
    return accountCreationTx, expectedAddress, nil
}

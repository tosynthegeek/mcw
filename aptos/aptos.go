package aptos

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"mcw/client"
	"mcw/types"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

func WalletFromMnemonic(mnemonic string, passphrase string) (types.Wallet, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
        log.Fatal("Mnemonic is not valid")
    }

	// Convert mnemonic to seed
    seed := bip39.NewSeed(mnemonic, passphrase)

    // Derive the private key using PBKDF2
    derivationPath := "m/44'/637'/0'/0'/0'"
    privateKeyBytes := pbkdf2.Key(seed, []byte(derivationPath), 2048, ed25519.SeedSize, sha256.New)
    // Create Aptos account from private key
	privateKey := ed25519.NewKeyFromSeed(privateKeyBytes)
	// Create an authentication key
	signer:= &crypto.Ed25519PrivateKey{
		Inner: privateKey,
	}

	authKey:= signer.AuthKey()
    aptosAccount, err:= aptos.NewAccountFromSigner(signer, *authKey)
    if err != nil {
        fmt.Errorf("failed to create Aptos account: %w", err)
    }

    address:= aptosAccount.Address.String()
	accountAddress:= aptosAccount.AccountAddress()
	pubKey:= aptosAccount.PubKey()

	fmt.Println(accountAddress)

	return types.Wallet {
		Mnemonic: mnemonic,
		PrivateKey: aptos.BytesToHex(privateKey),
		PublicKey: pubKey.ToHex(),
		Address: address,
	}, nil
}

func CreateWallet(passphrase string) (types.Wallet, error) {
    entropy, err:= bip39.NewEntropy(128) // 12 words
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error creating entropy: %w", err)
    }
    mnemonic, err:= bip39.NewMnemonic(entropy)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error generating mnemonic: %w", err)
    }
    
    wallet, err:= WalletFromMnemonic(mnemonic, passphrase)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("error creating wallet: %w", err)
	}

	return types.Wallet{
		Mnemonic: wallet.Mnemonic,
		PublicKey: wallet.PublicKey,
		PrivateKey: wallet.PrivateKey,
		Address: wallet.Address,
	}, nil
}

func GetBalance(bp types.BalanceParam) (types.Balance, error) {
	client, err:= aptos.NewClient(bp.AptosConfig)
	if err != nil {
		return types.Balance{}, fmt.Errorf("failed to create Aptos client: %w", err)
	}

	aptosAddress:= bp.AptosAddress
	
	balance, err:= client.AccountAPTBalance(aptosAddress)
	if err != nil {
		return types.Balance{}, fmt.Errorf("failed to get account balance: %w", err)
	}

	return types.Balance{
		Address: aptosAddress.String(),
		Balance: string(balance),
	}, nil
}

func GetTokenBalance(tbp types.TBParam) (types.TokenBalance, error) {

	client, err:= client.AptosClient(tbp.AptosConfig)
	if err != nil {
		return types.TokenBalance{}, fmt.Errorf("failed to create Aptos client: %w", err)
	}
	
	balances, err:= client.GetCoinBalances(tbp.AptosAddress)
	if err != nil {
		return types.TokenBalance{}, fmt.Errorf("failed to get coin balances: %w", err)
	}

	return types.TokenBalance{
		Address: string(tbp.Address),
		Data: balances,
	}, nil
}

func GetTxByHash(hp types.HashParam) (types.TransactionByHash, error) {
	client, err:= client.AptosClient(hp.AptosConfig)
	if err != nil {
		return types.TransactionByHash{}, fmt.Errorf("failed to create Aptos client: %w", err)
	}
	
	tx, err:= client.TransactionByHash(hp.Hash)
	if err != nil {
		return types.TransactionByHash{}, fmt.Errorf("failed to get transaction by hash: %w", err)
	}

	return types.TransactionByHash{
		Transaction: tx,
	}, nil
}

func Transfer(tp types.TransferParam) (types.TransferData, error) {
	client, err:= aptos.NewClient(tp.AptosConfig) // Use appropriate network
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to create Aptos client: %w", err)
	}

	senderPrivKeyBytes, err := hex.DecodeString(tp.PrivateKey)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("invalid sender private key: %w", err)
	}
	senderPrivKey := ed25519.PrivateKey(senderPrivKeyBytes)
	signer:= &crypto.Ed25519PrivateKey{
		Inner: senderPrivKey,
	}
	txSigner, err:= aptos.NewAccountFromSigner(signer, *signer.AuthKey())
	if err != nil {
		return types.TransferData{}, fmt.Errorf("error from signer: %w", err)
	}

	amount := tp.Amount
	toAddress := tp.AptosRecipient

	// Create a transaction payload
	txPayload, err := aptos.APTTransferTransaction(client, txSigner, toAddress, amount)

	signedTx, err:= txPayload.SignedTransaction(txSigner)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("error signing transaction: %w", err)
	}

	// Submit the transaction
	tx, err := client.SubmitTransaction(signedTx)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to submit transaction: %w", err)
	}
	txHash:= tx.Hash
	data, err:= client.WaitForTransaction(txHash)

	return types.TransferData{
		Hash: txHash,
		Data: data,
	}, nil
}

/*
TransferToken
GetTokenInfo
SmartContractCallls
*/
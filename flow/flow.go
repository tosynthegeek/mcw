package flow

import (
	"context"
	"fmt"
	"log"
	"mcw/types"

	"github.com/onflow/cadence"
	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/access/http"
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/onflow/flow-go-sdk/templates"
	"github.com/tyler-smith/go-bip39"
)

/* CreateWalletfromMnemonic generates a Flow wallet from a mnemonic phrase.
This function does not create an on-chain Flow account or address.
Instead, it generates a private/public key pair from the mnemonic and
prepares the information needed to create an account later.

A key pair alone does not constitute an account or address on Flow.
An actual account is created through a separate transaction on the blockchain.
Use CreateAccountCreationTx to prepare a transaction for creating an account
and to get an expected address for the new account.
*/
func WalletfromMnemonic(mnemonic string) (types.FlowWallet, error){
	seed:= []byte(mnemonic)

	privKey, err:= crypto.GeneratePrivateKey(crypto.ECDSA_P256, seed)
	if err != nil {
		return types.FlowWallet{}, fmt.Errorf("error generating private key: %w", err)
	}

	pubKey:= privKey.PublicKey()

    return types.FlowWallet{
        Mnemonic:      mnemonic,
        PrivateKey:    privKey,
        PublicKey:     pubKey,
        KeyIndex:      0,
        SignatureAlgo: crypto.ECDSA_P256,
        HashAlgo:      crypto.SHA3_256,
    }, nil
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
func CreateAccountCreationTx(wallet types.FlowWallet, payer flow.Address, network flow.ChainID)  (*flow.Transaction, flow.Address, error){
    accountCreationTx, err := templates.CreateAccount([]*flow.AccountKey{
        &flow.AccountKey{
            PublicKey: wallet.PublicKey,
            SigAlgo:   wallet.SignatureAlgo,
            HashAlgo:  wallet.HashAlgo,
            Weight:    flow.AccountKeyWeightThreshold,
        },
    }, nil, payer)
    
    if err != nil {
        return nil, flow.EmptyAddress, fmt.Errorf("failed to create account creation transaction: %w", err)
    }

    // Calculate the expected address of the new account
    expectedAddress := flow.NewAddressGenerator(network).NextAddress()
    
    return accountCreationTx, expectedAddress, nil
}

func CreateWallet() (types.FlowWallet, error){
    entropy, err:= bip39.NewEntropy(128) // 12 words
    if err != nil {
        log.Fatal(err.Error())
    }
    mnemonic, err:= bip39.NewMnemonic(entropy)
    if err != nil {
        fmt.Errorf("error generating mnemonic: %w", err)
    }
    
    wallet, err:= WalletfromMnemonic(mnemonic)
	if err != nil {
		return types.FlowWallet{}, fmt.Errorf("error creating wallet: %w", err)
	}

    return wallet, err
}

func GetAccountBalance(address string, network string) (uint64, error) {
	var host string
	switch network {
	case "mainnet":
		host = "access.mainnet.nodes.onflow.org:9000"
	case "testnet":
		host = "access.devnet.nodes.onflow.org:9000"
	case "emulator":
		host = "127.0.0.1:3569"
	default:
		return 0, fmt.Errorf("invalid network: %s", network)
	}
	client, err:= http.NewClient(host)
	if err != nil {
		return 0, fmt.Errorf("failed to create Flow client: %v", err)
	}
	defer client.Close()

	flowAddress := flow.HexToAddress(address)
	account, err := client.GetAccount(context.Background(), flowAddress)
	if err != nil {
		return 0, fmt.Errorf("failed to get account: %v", err)
	}

	return account.Balance, nil
}

func GetTxByHash(hash string, host string) (*flow.Transaction, error) {
	client, err:= http.NewClient(host)
	if err != nil {
		return &flow.Transaction{}, fmt.Errorf("error connecting to client: %w", err)
	}
	id:= flow.HexToID(hash)
	tx, err:= client.GetTransaction(context.Background(), id)
	if err != nil {
		return &flow.Transaction{}, fmt.Errorf("error getting transaction: %w", err)
	}

	return tx, err
}

func Transfer(transferPayload types.FlowTransferPayload) (*flow.TransactionResult, error) {
	client, err:= http.NewClient(transferPayload.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Flow Access API: %w", err)
	}
	defer client.Close()

	privKey, err:= crypto.DecodePrivateKeyHex(crypto.ECDSA_P256, transferPayload.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)

	}
	senderAccount, err:= client.GetAccount(context.Background(), transferPayload.Sender)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sender account: %w", err)
	}

	signer, err:= crypto.NewInMemorySigner(privKey, senderAccount.Keys[0].HashAlgo)

	amount, err:= cadence.NewUFix64(transferPayload.Amount)

	tx:= flow.NewTransaction().
		SetScript(transferPayload.Script).
		SetProposalKey(transferPayload.Sender, 0, 0).
		SetPayer(transferPayload.Sender).
		AddAuthorizer(transferPayload.Sender)

	tx.AddArgument(amount)
    tx.AddArgument(cadence.NewAddress(transferPayload.Recipient))

	latestBlock, err := client.GetLatestBlock(context.Background(), true)
    if err != nil {
        return nil, fmt.Errorf("failed to get latest block: %w", err)
    }

	tx.SetReferenceBlockID(latestBlock.ID)

    err = tx.SignEnvelope(transferPayload.Sender, 0, signer)
    if err != nil {
        return nil, fmt.Errorf("failed to sign transaction: %w", err)
    }

	err = client.SendTransaction(context.Background(), *tx)
    if err != nil {
        return nil, fmt.Errorf("failed to send transaction: %w", err)
    }

    result, err := client.GetTransactionResult(context.Background(), tx.ID())
    if err != nil {
        return nil, fmt.Errorf("failed to get transaction result: %w", err)
    }

    return result, nil
}

/*
GetTxByHash
Transfer
GetTokenInfo
SC Calls
*/
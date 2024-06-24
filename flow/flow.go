package flow

import (
	"context"
	"encoding/hex"
	"errors"
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

type Flow struct {
    Host		string
}

var ErrUnsupportedOperation = errors.New("operation not supported for this blockchain")

/* CreateWalletfromMnemonic generates a Flow wallet from a mnemonic phrase.
This function does not create an on-chain Flow account or address.
Instead, it generates a private/public key pair from the mnemonic and
prepares the information needed to create an account later.

A key pair alone does not constitute an account or address on Flow.
An actual account is created through a separate transaction on the blockchain.
Use CreateAccountCreationTx to prepare a transaction for creating an account
and to get an expected address for the new account.
*/
func (f Flow) WalletFromMnemonic(wp types.WalletParam) (types.Wallet, error){
	seed:= []byte(wp.Mnemonic)

	privKey, err:= crypto.GeneratePrivateKey(crypto.ECDSA_P256, seed)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("error generating private key: %w", err)
	}

	pubKey:= privKey.PublicKey()

    return types.Wallet{
        Mnemonic:      wp.Mnemonic,
        PrivateKey:    privKey.String(),
        PublicKey:     pubKey.String(),
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
func CreateAccountCreationTx(wallet types.Wallet, payer flow.Address, network flow.ChainID)  (*flow.Transaction, flow.Address, error){
	publicKeyBytes, err := hex.DecodeString(wallet.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}
	pubKey, err:= crypto.DecodePublicKey(crypto.ECDSA_P256, publicKeyBytes)
	if err != nil {
		log.Fatal(err.Error())
	}
	accountCreationTx, err := templates.CreateAccount([]*flow.AccountKey{
        &flow.AccountKey{
            PublicKey: pubKey,
            SigAlgo:   crypto.ECDSA_P256,
            HashAlgo:  crypto.SHA3_256,
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

func (f Flow) CreateWallet(cwp types.CWParam) (types.Wallet, error) {
    entropy, err:= bip39.NewEntropy(128) // 12 words
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error generating entropy: %w", err)
    }
    mnemonic, err:= bip39.NewMnemonic(entropy)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error generating mnemonic: %w", err)
    }

	wp:= types.WalletParam {
		Mnemonic: mnemonic,
	}
    
    wallet, err:= f.WalletFromMnemonic(wp)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("error creating wallet: %w", err)
	}

    return wallet, err
}

func (f Flow) GetBalance(bp types.BalanceParam) (types.Balance, error) {
	client, err:= http.NewClient(bp.EndpointURL)
	if err != nil {
		return types.Balance{}, fmt.Errorf("failed to create Flow client: %v", err)
	}
	defer client.Close()

	flowAddress := flow.HexToAddress(bp.Address)
	account, err := client.GetAccount(context.Background(), flowAddress)
	if err != nil {
		return types.Balance{}, fmt.Errorf("failed to get account: %v", err)
	}

	return types.Balance{
		Address: bp.Address,
		Balance: string(account.Balance),
	}, nil
}

func (f Flow) GetTxByHash(hp types.HashParam) (types.TransactionByHash, error) {
	client, err:= http.NewClient(hp.EndpointURL)
	if err != nil {
		return types.TransactionByHash{}, fmt.Errorf("error connecting to client: %w", err)
	}
	id:= flow.HexToID(hp.Hash)
	tx, err:= client.GetTransaction(context.Background(), id)
	if err != nil {
		return types.TransactionByHash{}, fmt.Errorf("error getting transaction: %w", err)
	}

	return types.TransactionByHash{
		Transaction: tx,
	}, err
}

func (f Flow) Transfer(tp types.TransferParam) (types.TransferData, error) {
	client, err:= http.NewClient(tp.EndpointURL)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to connect to Flow Access API: %w", err)
	}
	defer client.Close()

	privKey, err:= crypto.DecodePrivateKeyHex(crypto.ECDSA_P256, tp.PrivateKey)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to decode private key: %w", err)
	}
	
	senderAccount, err:= client.GetAccount(context.Background(), tp.FlowSender)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to fetch sender account: %w", err)
	}

	signer, err:= crypto.NewInMemorySigner(privKey, senderAccount.Keys[0].HashAlgo)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("error initializing new in-memory signer: %w", err)
	}

	amount:= cadence.NewInt64(int64(tp.Amount))

	tx:= flow.NewTransaction().
		SetScript(tp.Script).
		SetProposalKey(tp.FlowSender, 0, 0).
		SetPayer(tp.FlowSender).
		AddAuthorizer(tp.FlowSender)

	tx.AddArgument(amount)
    tx.AddArgument(cadence.NewAddress(tp.FlowRecipient))

	latestBlock, err := client.GetLatestBlock(context.Background(), true)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("failed to get latest block: %w", err)
    }

	tx.SetReferenceBlockID(latestBlock.ID)

    err = tx.SignEnvelope(tp.FlowSender, 0, signer)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("failed to sign transaction: %w", err)
    }

	err = client.SendTransaction(context.Background(), *tx)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("failed to send transaction: %w", err)
    }

    result, err := client.GetTransactionResult(context.Background(), tx.ID())
    if err != nil {
        return types.TransferData{}, fmt.Errorf("failed to get transaction result: %w", err)
    }

    return types.TransferData{
		Hash: result.BlockID.String(),
		Data: result,
	}, nil
}

func (f Flow) GetTokenBalance(tbp types.TBParam) (types.TokenBalance, error) {
	return types.TokenBalance{}, ErrUnsupportedOperation
}

func (f Flow) GetAddressFromPrivateKey(privateKey string) (types.Address, error) {
	return types.Address{}, ErrUnsupportedOperation
}

func (f Flow) TransferToken(ttp types.TransferTokenParam) (types.TransferData, error) {
	return types.TransferData{}, ErrUnsupportedOperation
}

func (f Flow) GetTokenInfo(tip types.TokenInfoParam) (types.TokenInfo, error) {
	return types.TokenInfo{}, ErrUnsupportedOperation
}

func (f Flow) SmartContractCall(payload types.SmartContractCallPayload) ([]interface{}, error) {
	return nil, ErrUnsupportedOperation
}
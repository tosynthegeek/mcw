package sol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/tosynthegeek/mcw/sol/internal"
	"github.com/tosynthegeek/mcw/types"

	solClient "github.com/blocto/solana-go-sdk/client"
	"github.com/blocto/solana-go-sdk/common"
	"github.com/blocto/solana-go-sdk/program/system"
	"github.com/blocto/solana-go-sdk/program/token"
	soltypes "github.com/blocto/solana-go-sdk/types"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

type Solana struct {
	EndpointURL		string // endpoint for sol, rpcurl for eth
}

var ErrUnsupportedOperation = errors.New("operation not supported for this blockchain")

// WalletFromMnemonic creates a Solana account from a given mnemonic and passphrase (password) using the derivation path "m/44'/501'/0'/0"
// It returns a Wallet struct containing the mnemonic, private key, public key, and address.
func (s Solana) WalletFromMnemonic(wp types.WalletParam) (types.Wallet, error) {
	if !bip39.IsMnemonicValid(wp.Mnemonic) {
        return types.Wallet{}, fmt.Errorf("Mnemonic is not valid")
    }

	// Generate seed from mnemonic and passphrase
    seed := bip39.NewSeed(wp.Mnemonic, wp.Passphrase)
    
    // Generate master key from seed
    masterKey, err := bip32.NewMasterKey(seed)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to create master key: %w", err)
    }

	// Derive the path m/44'/501'/0'/0'
    purpose, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive purpose key: %w", err)
    }

	coinType, err := purpose.NewChildKey(bip32.FirstHardenedChild + 501)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive coin type key: %w", err)
    }

    account, err := coinType.NewChildKey(bip32.FirstHardenedChild + 0)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive account key: %w", err)
    }

    change, err := account.NewChildKey(bip32.FirstHardenedChild + 0)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive change key: %w", err)
    }

    // Create Solana account from the private key
    privateKeyBytes := change.Key[:32] // Solana private key is 32 bytes
    solAccount, err:= soltypes.AccountFromSeed(privateKeyBytes)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("error getting account from seed: %w", err)
	}

	privateKeyFull := append(solAccount.PrivateKey[:32], solAccount.PublicKey[:]...)
    privateKeyJSON, err := json.Marshal(privateKeyFull)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("Error encoding private key: %v", err)
    }
    // Construct and return the wallet
    return types.Wallet{
        Mnemonic:   wp.Mnemonic,
        PrivateKey: string(privateKeyJSON),
        PublicKey:  solAccount.PublicKey.String(),
        Address:    solAccount.PublicKey.ToBase58(),
	}, nil
}

func (s Solana) CreateWallet(cwp types.CWParam) (types.Wallet, error) {
    entropy, err:= bip39.NewEntropy(128) // 12 words
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error generating entropy: %w", err)
    }
    mnemonic, err:= bip39.NewMnemonic(entropy)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error creating mnemonic: %w", err)
    }
	
	wp:= types.WalletParam {
		Mnemonic: mnemonic,
		Passphrase: cwp.Passphrase,
	}
    
    wallet, err:= s.WalletFromMnemonic(wp)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("error creating mnemonic: %w", err)
	}

    return wallet, nil
}


func (s Solana) GetAddressFromPrivateKey(privateKey string) (types.Address, error) {
	privateKeyJSON, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return types.Address{}, fmt.Errorf("error decoding base64: %v", err)
	}

	privateKeyBytes := privateKeyJSON[:64]
	wallet, err := soltypes.AccountFromBytes(privateKeyBytes)
	if err != nil {
		return types.Address{}, fmt.Errorf("error creating Solana account: %v", err)
	}

	return types.Address{
		Address:    wallet.PublicKey.ToBase58(),
		PrivateKey: base64.StdEncoding.EncodeToString(privateKeyBytes),
	}, nil
}

// GetSolBalance
func (s Solana) GetBalance(bp types.BalanceParam) (types.Balance, error) {
	client:= solClient.NewClient(bp.EndpointURL)

	balance, err:= client.GetBalance(bp.Context, bp.Address)
	if err != nil {
		return types.Balance{}, fmt.Errorf("error fetching balance: %w", err)
	}

	return types.Balance{
		Address: bp.Address,
		Balance: string(balance),
	}, nil
}

// GetTokenBalance
func (s Solana) GetTokenBalance(bp types.TBParam) (types.TokenBalance, error) {
	client:= solClient.NewClient(bp.EndpointURL)
	resp, err:= client.GetTokenAccountsByOwnerByMint(bp.Context, bp.Address, bp.TokenAddress)
	if err != nil {
		log.Fatal(err.Error())
	}

    if len(resp) == 0 {
		return types.TokenBalance{}, fmt.Errorf("no token accounts found for address: %s", bp.Address)
	}

    tokenAccount := resp[0].PublicKey

	// Fetch the balance for the token account
	balanceResp, err := client.GetTokenAccountBalance(bp.Context, tokenAccount.ToBase58())
	if err != nil {
        return types.TokenBalance{}, fmt.Errorf("error fetching token balance: %w", err)
	}

    return types.TokenBalance{
		Address: bp.Address,
		Data: balanceResp,
	}, nil
}

// GetTxByHash
func (s Solana) GetTxByHash(hp types.HashParam) (types.TransactionByHash, error) {
	client:= solClient.NewClient(hp.EndpointURL)
	tx, err:= client.GetTransaction(hp.Context, hp.Hash)
	if err != nil {
		return types.TransactionByHash{}, fmt.Errorf("error getting transaction: %w", err)
	}

	return types.TransactionByHash{
		Transaction: tx,
	}, nil
}

// TransferSol
func (s Solana) Transfer(tp types.TransferParam) (types.TransferData, error) {
	client:= solClient.NewClient(tp.EndpointURL)
	privateKey, err:= base64.StdEncoding.DecodeString(tp.PrivateKey)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to decode private key: %w", err)
	}

	sender, err:= soltypes.AccountFromBytes(privateKey)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to create account from private key: %w", err)
	}

	recipient:= common.PublicKeyFromString(tp.Recipient)
	fmt.Println("Recipient: ", recipient)
	
	value, err:= client.GetLatestBlockhash(tp.Context)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to get latest blockhash: %w", err)
	}

	latestBlockHash:= value.Blockhash

	tx, err:= soltypes.NewTransaction(soltypes.NewTransactionParam{
		Signers: []soltypes.Account{sender},
		Message: soltypes.NewMessage(soltypes.NewMessageParam{
			FeePayer: sender.PublicKey,
			RecentBlockhash: latestBlockHash,
			Instructions: []soltypes.Instruction{
				system.Transfer(system.TransferParam{
					From: sender.PublicKey,
					To: recipient,
					Amount: tp.Amount,
				}),
			},
		}),
	})
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to create transaction: %w", err)
	}

	txHash, err := client.SendTransaction(tp.Context, tx)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to send transaction: %w", err)
	}
	fmt.Println(txHash)

	return types.TransferData{
		Hash: txHash,
		Data: tx,
	}, nil
}

// Transfer 
func (s Solana) TransferToken(ttp types.TransferTokenParam) (types.TransferData, error) {
	client:= solClient.NewClient(ttp.EndpointURL)
	privateKey, err:= base64.StdEncoding.DecodeString(ttp.PrivateKey)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to decode private key: %w", err)
	}

	sender, err:= soltypes.AccountFromBytes(privateKey)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to create account from private key: %w", err)
	}

	recipient:= common.PublicKeyFromString(ttp.Recipient)
	mintPubkey := common.PublicKeyFromString(ttp.Token)

	// Get token accounts
    fromTokenAccount, _, err := common.FindAssociatedTokenAddress(sender.PublicKey, mintPubkey)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("failed to find sender's associated token address: %w", err)
    }

    toTokenAccount, _, err := common.FindAssociatedTokenAddress(recipient, mintPubkey)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("failed to find recipient's associated token address: %w", err)
    }
	
	value, err:= client.GetLatestBlockhash(ttp.Context)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to get latest blockhash: %w", err)
	}

	latestBlockHash:= value.Blockhash

	tx, err:= soltypes.NewTransaction(soltypes.NewTransactionParam{
		Signers: []soltypes.Account{sender},
		Message: soltypes.NewMessage(soltypes.NewMessageParam{
			FeePayer: sender.PublicKey,
			RecentBlockhash: latestBlockHash,
			Instructions: []soltypes.Instruction{
				token.Transfer(token.TransferParam{
					From: fromTokenAccount,
					To: toTokenAccount,
					Auth: sender.PublicKey,
					Amount: ttp.Amount,
					Signers: []common.PublicKey{sender.PublicKey},
				}),
			},
		}),
	})
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to create transaction: %w", err)
	}

	txHash, err := client.SendTransaction(ttp.Context, tx)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to send transaction: %w", err)
	}
	fmt.Println(txHash)

	return types.TransferData{
		Hash: txHash,
		Data: tx,
	}, nil

}

// GetTokenInfo not working yet 
func (s Solana) GetTokenInfo(tip types.TokenInfoParam) (types.TokenInfo, error){
	client:= solClient.NewClient(tip.EndpointURL)

	mintAccountInfo, err:= client.GetAccountInfo(tip.Context, tip.TokenAddress)
	if err != nil {
		return types.TokenInfo{}, fmt.Errorf("failed to get account info: %w", err)
	}

	// Check if the account is owned by the Token Program
    tokenProgramID := common.TokenProgramID
    if mintAccountInfo.Owner != tokenProgramID {
        return types.TokenInfo{}, fmt.Errorf("account is not owned by the Token Program (owner: %s)", mintAccountInfo.Owner)
    }

	// if len(mintAccountInfo.Data) != 165 {
	// 	return types.TokenInfo{}, fmt.Errorf("invalid account data size: expected 165 bytes, got %d", len(mintAccountInfo.Data))
	// }

	mintAccount, err:= token.MintAccountFromData(mintAccountInfo.Data)
	if err != nil {
		return types.TokenInfo{}, fmt.Errorf("failed to parse token account data: %w", err)
	}


	mint:= common.PublicKeyFromString(tip.TokenAddress)

	// // mintAddress:= mint.ToBase58()
	// mintAccountInfo, err := client.GetAccountInfo(ctx, tokenAddress)
    // if err != nil {
    //     return types.TokenInfo{}, fmt.Errorf("failed to get mint account info: %w", err)
    // }

    // // Parse mint account data
    // mintInfo, err := token.MintAccountFromData(mintAccountInfo.Data)
    // if err != nil {
    //     return types.TokenInfo{}, fmt.Errorf("failed to parse mint account data: %w", err)

    // }
	metadata, err:= internal.GetTokenMetadata(tip.EndpointURL, tip.Context, mint)
	if err != nil {
		return types.TokenInfo{}, fmt.Errorf("failed to get token metadata: %w", err)
	}

	return types.TokenInfo {
		Name: metadata.Name,
		Symbol: metadata.Symbol,
		URL: metadata.URL,
		Supply: *big.NewInt(int64(mintAccount.Supply)),
		Mint: mint,
		Decimals:  mintAccount.Decimals,
		Owner: mintAccountInfo.Owner,
		MintAuthority: *mintAccount.MintAuthority,
		FreezeAuthority: *mintAccount.FreezeAuthority,
		IsInitialize: mintAccount.IsInitialized,
		AssociatedAccount: tip.TokenAddress,
	}, nil
}

func (s *Solana) SmartContractCall(payload types.SmartContractCallPayload) (interface{}, error) {
    return nil, ErrUnsupportedOperation
}
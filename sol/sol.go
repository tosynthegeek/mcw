package sol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"mcw/types"

	solClient "github.com/blocto/solana-go-sdk/client"
	"github.com/blocto/solana-go-sdk/common"
	"github.com/blocto/solana-go-sdk/program/system"
	"github.com/blocto/solana-go-sdk/program/token"
	soltypes "github.com/blocto/solana-go-sdk/types"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// WalletFromMnemonic creates a Solana account from a given mnemonic and passphrase (password) using the derivation path "m/44'/501'/0'/0"
// It returns a Wallet struct containing the mnemonic, private key, public key, and address.
func WalletFromMnemonic(mnemonic string, passphrase string) types.Wallet {

	 if !bip39.IsMnemonicValid(mnemonic) {
        log.Fatal("Mnemonic is not valid")
    }

	// Generate seed from mnemonic and passphrase
    seed := bip39.NewSeed(mnemonic, passphrase)
    
    // Generate master key from seed
    masterKey, err := bip32.NewMasterKey(seed)
    if err != nil {
        log.Fatal(err.Error())
    }

	// Derive the path m/44'/501'/0'/0'
    purpose, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
    if err != nil {
        log.Fatal(err.Error())
    }

	coinType, err := purpose.NewChildKey(bip32.FirstHardenedChild + 501)
    if err != nil {
        log.Fatal(err.Error())
    }

    account, err := coinType.NewChildKey(bip32.FirstHardenedChild + 0)
    if err != nil {
        log.Fatal(err.Error())
    }

    change, err := account.NewChildKey(bip32.FirstHardenedChild + 0)
    if err != nil {
        log.Fatal(err.Error())
    }

    // Create Solana account from the private key
    privateKeyBytes := change.Key[:32] // Solana private key is 32 bytes
    solAccount, err:= soltypes.AccountFromSeed(privateKeyBytes)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(privateKeyBytes)
	privateKeyFull := append(solAccount.PrivateKey[:32], solAccount.PublicKey[:]...)
    privateKeyJSON, err := json.Marshal(privateKeyFull)
    if err != nil {
        log.Fatalf("Error encoding private key: %v", err)
    }
    // Construct and return the wallet
    return types.Wallet{
        Mnemonic:   mnemonic,
        PrivateKey: string(privateKeyJSON),
        PublicKey:  solAccount.PublicKey.String(),
        Address:    solAccount.PublicKey.ToBase58(),
	}
}

func CreateWallet(passphrase string) types.Wallet {
    entropy, err:= bip39.NewEntropy(128) // 12 words
    if err != nil {
        log.Fatal(err.Error())
    }
    mnemonic, err:= bip39.NewMnemonic(entropy)
    if err != nil {
        log.Fatal(err.Error())
    }
    
    wallet:= WalletFromMnemonic(mnemonic, passphrase)

    return wallet
}


func GetAddressFromPrivateKey(privateKey string) types.Address {
	privateKeyJSON, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		log.Fatalf("Error decoding base64: %v", err)
	}

	privateKeyBytes := privateKeyJSON[:64]
	wallet, err := soltypes.AccountFromBytes(privateKeyBytes)
	if err != nil {
		log.Fatalf("Error creating Solana account: %v", err)
	}

	return types.Address{
		Address:    wallet.PublicKey.ToBase58(),
		PrivateKey: base64.StdEncoding.EncodeToString(privateKeyBytes),
	}
}

// GetSolBalance
func GetSolBalance(endpoint string, ctx context.Context, address string) uint {
	client:= solClient.NewClient(endpoint)

	balance, err:= client.GetBalance(ctx, address)
	if err != nil {
		log.Fatal(err.Error())
	}

	return uint(balance)
}

// GetTokenBalance
func GetTokenBalance(endpoint string, ctx context.Context, address string, tokenMintAddress string) solClient.TokenAmount {
	client:= solClient.NewClient(endpoint)
	resp, err:= client.GetTokenAccountsByOwnerByMint(ctx, address, tokenMintAddress)
	if err != nil {
		log.Fatal(err.Error())
	}

    if len(resp) == 0 {
		fmt.Errorf("no token accounts found for address: %s", address)
	}

    tokenAccount := resp[0].PublicKey

	// Fetch the balance for the token account
	balanceResp, err := client.GetTokenAccountBalance(ctx, tokenAccount.ToBase58())
	if err != nil {
        fmt.Errorf("error fetching token balance: %w", err)
	}

    return balanceResp
}

// GetTxByHash
func GetTxByHash(endpoint string, ctx context.Context, hash string) (*solClient.Transaction) {
	client:= solClient.NewClient(endpoint)
	tx, err:= client.GetTransaction(ctx, hash)
	if err != nil {
		log.Fatal(err.Error())
	}

	return tx
}

// TransferSol
func TransferSol(transferPayload types.TransferSolPayload) (string, error) {
	client:= solClient.NewClient(transferPayload.RpcUrl)
	privateKey, err:= base64.StdEncoding.DecodeString(transferPayload.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	sender, err:= soltypes.AccountFromBytes(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create account from private key: %w", err)
	}

	recipient:= common.PublicKeyFromString(transferPayload.Recipient)
	fmt.Println("Recipient: ", recipient)
	
	value, err:= client.GetLatestBlockhash(transferPayload.Context)
	if err != nil {
		return "", fmt.Errorf("failed to get latest blockhash: %w", err)
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
					Amount: transferPayload.Amount,
				}),
			},
		}),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create transaction: %w", err)
	}

	txHash, err := client.SendTransaction(transferPayload.Context, tx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}
	fmt.Println(txHash)

	return txHash, nil
}

// Transfer 
func TransferToken(transferPayload types.TransferSolTokenPayload) (string, error) {
	client:= solClient.NewClient(transferPayload.RpcUrl)
	privateKey, err:= base64.StdEncoding.DecodeString(transferPayload.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	sender, err:= soltypes.AccountFromBytes(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create account from private key: %w", err)
	}

	recipient:= common.PublicKeyFromString(transferPayload.Recipient)
	mintPubkey := common.PublicKeyFromString(transferPayload.Mint)

	// Get token accounts
    fromTokenAccount, _, err := common.FindAssociatedTokenAddress(sender.PublicKey, mintPubkey)
    if err != nil {
        return "", fmt.Errorf("failed to find sender's associated token address: %w", err)
    }

    toTokenAccount, _, err := common.FindAssociatedTokenAddress(recipient, mintPubkey)
    if err != nil {
        return "", fmt.Errorf("failed to find recipient's associated token address: %w", err)
    }
	
	value, err:= client.GetLatestBlockhash(transferPayload.Context)
	if err != nil {
		return "", fmt.Errorf("failed to get latest blockhash: %w", err)
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
					Amount: transferPayload.Amount,
					Signers: []common.PublicKey{sender.PublicKey},
				}),
			},
		}),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create transaction: %w", err)
	}

	txHash, err := client.SendTransaction(transferPayload.Context, tx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}
	fmt.Println(txHash)

	return txHash, nil

}

// GetTokenInfo not working yet 
func GetTokenInfo(endpoint string, ctx context.Context, tokenAddress string) (types.SolTokenInfo, error){
	client:= solClient.NewClient(endpoint)

	mintAccountInfo, err:= client.GetAccountInfo(ctx, tokenAddress)
	if err != nil {
		return types.SolTokenInfo{}, fmt.Errorf("failed to get account info: %w", err)
	}

	// Check if the account is owned by the Token Program
    tokenProgramID := common.TokenProgramID
    if mintAccountInfo.Owner != tokenProgramID {
        return types.SolTokenInfo{}, fmt.Errorf("account is not owned by the Token Program (owner: %s)", mintAccountInfo.Owner)
    }

    // Log the size of the account data for debugging
    log.Printf("Account data size: %d bytes", len(mintAccountInfo.Data))

	// if len(mintAccountInfo.Data) != 165 {
	// 	return types.SolTokenInfo{}, fmt.Errorf("invalid account data size: expected 165 bytes, got %d", len(mintAccountInfo.Data))
	// }

	mintAccount, err:= token.MintAccountFromData(mintAccountInfo.Data)
	if err != nil {
		return types.SolTokenInfo{}, fmt.Errorf("failed to parse token account data: %w", err)
	}


	mint:= common.PublicKeyFromString(tokenAddress)
	// // mintAddress:= mint.ToBase58()
	// mintAccountInfo, err := client.GetAccountInfo(ctx, tokenAddress)
    // if err != nil {
    //     return types.SolTokenInfo{}, fmt.Errorf("failed to get mint account info: %w", err)
    // }

    // // Parse mint account data
    // mintInfo, err := token.MintAccountFromData(mintAccountInfo.Data)
    // if err != nil {
    //     return types.SolTokenInfo{}, fmt.Errorf("failed to parse mint account data: %w", err)

    // }
	metadata, err:= GetTokenMetadata(endpoint, ctx, mint)
	if err != nil {
		return types.SolTokenInfo{}, fmt.Errorf("failed to get token metadata: %w", err)
	}

	return types.SolTokenInfo {
		Name: metadata.Name,
		Symbol: metadata.Symbol,
		URL: metadata.URL,
		Supply: mintAccount.Supply,
		Mint: mint,
		Decimals:  mintAccount.Decimals,
		Owner: mintAccountInfo.Owner,
		MintAuthority: *mintAccount.MintAuthority,
		FreezeAuthority: *mintAccount.FreezeAuthority,
		IsInitialize: mintAccount.IsInitialized,
		AssociatedAccount: tokenAddress,
	}, nil
}

func GetTokenMetadata(endpoint string, ctx context.Context, mintAddress common.PublicKey) (types.TokenMetaData, error) {
	client:= solClient.NewClient(endpoint)
    metadataProgram := common.PublicKeyFromString("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s") // Metaplex Token Metadata Program
    metadataAddress, _, err := common.FindProgramAddress(
        [][]byte{
            []byte("metadata"),
            metadataProgram.Bytes(),
            mintAddress.Bytes(),
        },
        metadataProgram,
    )
	if err != nil {
	    return types.TokenMetaData{}, fmt.Errorf("failed to find metadata address: %w", err)
	}

    accountInfo, err := client.GetAccountInfo(ctx, metadataAddress.ToBase58())
    if err != nil {
        return types.TokenMetaData{}, fmt.Errorf("failed to get metadata account info: %w", err)
    }

	fmt.Println(accountInfo.Data)
    // This is a simplified parsing. You'll need to implement proper
    // deserialization based on the Token Metadata Program's data structure
    var metadata types.TokenMetaData

    // This assumes the metadata is stored as JSON. Adjust as necessary.
    err = json.Unmarshal(accountInfo.Data, &metadata)
    if err != nil {
        return types.TokenMetaData{}, fmt.Errorf("failed to parse metadata: %w", err)
    }

    fmt.Printf("Name: %s\n", metadata.Name)
    fmt.Printf("Symbol: %s\n", metadata.Symbol)
    fmt.Printf("URI: %s\n", metadata.URL)


	return metadata, nil
}

// SmartContractCalls
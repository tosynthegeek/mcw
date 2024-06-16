package sol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"mcw/client"
	"mcw/types"

	solClient "github.com/blocto/solana-go-sdk/client"
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
func GetSolBalance(ctx context.Context, address string) uint {
	client:= client.SolClient()

	balance, err:= client.GetBalance(ctx, address)
	if err != nil {
		log.Fatal(err.Error())
	}

	return uint(balance)
}

// GetTokenBalance
func GetTokenBalance(ctx context.Context, address string, tokenMintAddress string) solClient.TokenAmount {
	client:= client.SolClient()
	resp, err:= client.GetTokenAccountsByOwnerByMint(ctx, address, tokenMintAddress)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(resp)

    if len(resp) == 0 {
		fmt.Errorf("no token accounts found for address: %s", address)
	}

    tokenAccount := resp[0].PublicKey

	// Fetch the balance for the token account
	balanceResp, err := client.GetTokenAccountBalance(ctx, tokenAccount.ToBase58())
	if err != nil {
        fmt.Errorf("error fetching token balance: %w", err)
	}

    fmt.Println(balanceResp.Amount)

	// Convert balance to *big.Int
	// balance := big.NewInt(0)

    return balanceResp
	
}
// GetTxByHash

// TransferSol
// Transfer token
// GetTokenInfo
// SmartContractCalls
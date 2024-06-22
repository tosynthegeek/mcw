package aptos

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"log"
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

func GetBalance(balancePayload types.AptosBalancePayload) (uint64, error) {
	
	var config aptos.NetworkConfig
	switch balancePayload.Network {
	case "mainnet":
		config = aptos.MainnetConfig
	case "devnet":
		config = aptos.DevnetConfig
	case "local":
		config = aptos.LocalnetConfig
	default:
		config = aptos.MainnetConfig
	}

	client, err:= aptos.NewClient(config)
	if err != nil {
		log.Fatal(err.Error())
	}
	
	balance, err:= client.AccountAPTBalance(balancePayload.Address)
	if err != nil {
		log.Fatal(err.Error())
	}

	return balance, nil
}
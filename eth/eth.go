package eth

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"mcw/types"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// WalletFromMnemonic generates an Ethereum wallet from a given mnemonic and passphrase (password).
// It returns a Wallet struct containing the mnemonic, private key, public key, and address.
func WalletFromMnemonic(mnemonic string, passphrase string) types.Wallet {

    fmt.Println("we have a connection")
    fmt.Println("Check if Mnemonic is valid")

    if !bip39.IsMnemonicValid(mnemonic) {
        log.Fatal("Mnemonic is not valid")
    }

    fmt.Println("Your mnemonic phrase: ", mnemonic)

    // Generate seed from mnemonic and passphrase
    seed := bip39.NewSeed(mnemonic, passphrase)
    fmt.Printf("Seed: %x\n", seed)

    // Generate master key from seed
    masterKey, err := bip32.NewMasterKey(seed)
    if err != nil {
        log.Fatal(err.Error())
    }

    fmt.Println("Generating Key....")

    // Use BIP-44 derivation path for Ethereum: m/44'/60'/0'/0/0
    purpose, err := masterKey.NewChildKey(44)
    if err != nil {
        log.Fatal(err.Error())
    }

    coinType, err := purpose.NewChildKey(60)
    if err != nil {
        log.Fatal(err.Error())
    }

    account, err := coinType.NewChildKey(0)
    if err != nil {
        log.Fatal(err.Error())
    }

    change, err := account.NewChildKey(0)
    if err != nil {
        log.Fatal(err.Error())
    }

    addressIndex, err := change.NewChildKey(0)
    if err != nil {
        log.Fatal(err.Error())
    }

    // Obtain and print the private key from the derived key
    key := addressIndex.Key
    ecdsaKey, err:= crypto.ToECDSA(key)
    if err != nil {
        log.Fatal(err.Error())
    }
    bytesKey:= crypto.FromECDSA(ecdsaKey)
    privateKey:= hexutil.Encode(bytesKey)[2:]

    fmt.Println("Private Key: ", privateKey) // 1efd19848ac5539bcc848450f8d8cf4dc9ceb7de95c7a80e209a1d84546f2b79

    publicKeyCrypto := ecdsaKey.Public()
    publicKeyEcdsa, ok:= publicKeyCrypto.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal(err.Error())
    }

    publicKeyBytes := crypto.FromECDSAPub(publicKeyEcdsa)
    publicKey:= hexutil.Encode(publicKeyBytes)[4:]
    address:= crypto.PubkeyToAddress(*publicKeyEcdsa).Hex()

    fmt.Println("Public Key: ", publicKey)  // 8b4dfac98e48e3e9408962fc995732977c22354e2499d65e47c912cc7ffd4c58699bb57d4b2c921d08311722d70678ad4cd7cbe605b25b1797549e7f0e220d2f
    fmt.Println("Ethereum Address: ", address) // 0xF890496Ac661FC846F6F0eB43c33947833c11bf8

    wallet:= types.Wallet {
        Mnemonic:   mnemonic,
        PrivateKey: privateKey,
        PublicKey:  publicKey,
        Address:    address,
    }
    return wallet
}

// CreateWallet generates a wallet from a given passphrase (password),
// and returns a Wallet struct containing the mnemonic, private key, public key, and Ethereum address.
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

    fmt.Println("Mnemonic: ", mnemonic)
    fmt.Println("Private Key: ", wallet.PrivateKey)
    fmt.Println("Public Key: ", wallet.PublicKey)
    fmt.Println("Address: ", wallet.Address)

    return wallet
}

// Get address from Private Key
func GetAddressFromPrivKateKey(privateKey string) types.Address {
    privKeyBytes, err := hex.DecodeString(privateKey)
    if err != nil {
        fmt.Println("Error Decoding Private Key: ", err)
    }

    privateKeyECDSA, err := crypto.ToECDSA(privKeyBytes)
    if err != nil {
        fmt.Println("Error: ", err)
    }

    publicKeyCrypto := privateKeyECDSA.Public()
    publicKeyEcdsa, ok:= publicKeyCrypto.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal(err.Error())
    }
    address:= crypto.PubkeyToAddress(*publicKeyEcdsa).Hex()
    fmt.Println("Address: ", address)
    
    return types.Address {
        Address: address,
        PrivateKey: privateKey,
    }
}

// Get Tx History for address
// Get Balance
// Transfer ETH
// Transfer other tokens
// Get Tx using the hash
// Get Token Info
// SC call
// Get Contract
package eth

import (
	"crypto/ecdsa"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// HardenedOffset is the constant used for hardened key derivation
// const HardenedOffset = 0x80000000

// WalletFromMnemonic generates a wallet from a given mnemonic and passphrase,
// and prints the mnemonic, seed, private key, public key, and Ethereum address.
func WalletFromMnemonic(mnemonic string, passphrase string) {

    fmt.Println("we have a connection")
    fmt.Println("Your mnemonic phrase:")
    fmt.Println(mnemonic)

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
    privateKey := addressIndex.Key
    fmt.Printf("Private Key: %x\n", privateKey)
    privateKeyEcdsa, err:= crypto.ToECDSA(privateKey)
    if err != nil {
        log.Fatal(err.Error())
    }
    privateKeyBytes:= crypto.FromECDSA(privateKeyEcdsa)
    fmt.Println("Private Key Stripped: ")
    fmt.Println(hexutil.Encode(privateKeyBytes)[2:])
    publicKeyCrypto :=privateKeyEcdsa.Public()
    publicKeyEcdsa, ok:= publicKeyCrypto.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal(err.Error())
    }

    publicKeyBytes := crypto.FromECDSAPub(publicKeyEcdsa)
    fmt.Println("Public Key: ")
    fmt.Println(hexutil.Encode(publicKeyBytes)[4:])   
    address := crypto.PubkeyToAddress(*publicKeyEcdsa).Hex()
    fmt.Println("Try Go Ethereum Address: ")
    fmt.Println(address)  
}
//Create wallet
// Get Contract
// Get Tx History for address
// Get address from Private Key
// Get Balance
// Transfer ETH
// Transfer other tokens
// Get Tx using the hash
// Get Token Info
// SC call
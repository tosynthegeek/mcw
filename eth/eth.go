package eth

import (
	"fmt"
	"log"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

// HardenedOffset is the constant used for hardened key derivation
const HardenedOffset = 0x80000000

// WalletFromMnemonic generates a wallet from a given mnemonic and passphrase,
// and prints the mnemonic, seed, private key, public key, and Ethereum address.
func WalletFromMnemonic(mnemonic string, passphrase string) {
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
    fmt.Printf("Private Key: %x\n",masterKey)

    fmt.Println("Generating Key...")

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

    // Obtain the public key from the derived key
    pubKey := addressIndex.PublicKey().Key
    fmt.Printf("Public Key: %x\n", pubKey)

    // Compute Ethereum address by hashing the public key with Keccak256
    hash := sha3.NewLegacyKeccak256()
    hash.Write(pubKey[1:]) // Exclude the first byte (format byte)
    address := hash.Sum(nil)

    fmt.Println("Ethereum Address (Hex):")
    fmt.Printf("0x%x\n", address[12:])
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
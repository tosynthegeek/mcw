# Multichain Wallet (MCW)

MCW is a Go package that provides a unified interface for managing wallets, generating mnemonics, and interacting with different blockchain networks: Ethereum, Solana, Bitcoin, and Aptos.The interface includes functionality for creating and managing wallets, handling transactions, and performing other blockchain-related operations.

## Installation

```go
go get ...
```

## Usage

Import the package in your Go code:

```go
import "github.com/tosynthegeek/mcw/wallet"
```

## Methods

- GenerateMnemonic
- WalletFromMnemonic
- CreateWallet
- GetAddressFromPrivateKey
- GetBalance
- GetTokenBalance
- GetTxByHash
- Transfer
- TransferToken
- GetTokenInfo
- SmartContractCall

### GenerateMnemonic

Generates a BIP-39 mnemonic phrase based on the specified entropy bit size. EThe mnemonic phrase is generated based on a specific bit size of entropy (randomness). 128 bits of entropy gives a 12-word mnemonic. 160 bits of entropy gives a 15-word mnemonic. 192 bits of entropy gives an 18-word mnemonic. 224 bits of entropy gives a 21-word mnemonic. 256 bits of entropy gives a 24-word mnemonic.

```go
bitsize:= 128
mnemonic, err := wallet.GenerateMnemonic(bitsize)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Mnemonic:", mnemonic)
}
```

- **Output**

```
Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

### WalletFromMnemonic

WalletFromMnemonic generates a wallet for a specified network using a given mnemonic phrase and passphrase. It takes in mnemonic, passphrase and network in a `types.WalletParam` struct. It returns a Wallet struct containing the mnemonic, private key, public key, and address.

It supports Ethereum, Solana, Bitcoin, and Aptos

```go
mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
passphrase:= "mysecretpassword"
network:= "ethereum"
wp:= types.WalletParam {
    Mnemonic: mnemonic,
    Passphrase: passphrase,
    Network: network,
}
wallet, err:= wallet.WalletFromMnemonic(wp)
if err != nil {
    fmt.Println("Error:", err)
}

fmt.Printf("Mnemonic: %s\n", wallet.Mnemonic)
fmt.Printf("Private Key: %s\n", wallet.PrivateKey)
fmt.Printf("Public Key: %s\n", wallet.PublicKey)
fmt.Printf("Address: %s\n", wallet.Address)
```

- **Output**

```go
    Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about,
    PrivateKey: 5e62984d8bda6a40bbdb08496b1d3f6f5e1be8b1fe4a575d18b9e0f5934eac4d,
    PublicKey: 0360ec40d4ec3132b3c5d6d9b4cddf8e17bb2c0e9e20d69e2e0bb9f9d7f9d20d6f,
    Address: 0x1234567890123456789012345678901234567890
```

### CreateWallet

CreateWallet generates a new wallet for a specified network. It takes in network and other parameters in a `types.CWParam` struct. It returns a Wallet struct containing the mnemonic, private key, public key, and address.

```go
cwp := types.CWParam{
    Network: "ethereum",
    Passphrase: "mysecretpassword",
}
wallet, err := wallet.CreateWallet(cwp)
if err != nil {
    fmt.Println("Error:", err)
}
```

- **Output**

```go
    Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about,
    PrivateKey: 5e62984d8bda6a40bbdb08496b1d3f6f5e1be8b1fe4a575d18b9e0f5934eac4d,
    PublicKey: 0360ec40d4ec3132b3c5d6d9b4cddf8e17bb2c0e9e20d69e2e0bb9f9d7f9d20d6f,
    Address: 0x1234567890123456789012345678901234567890
```

## Error Handling

Errors in the interface are returned in Go's idiomatic way as the second return value. The error messages provide detailed information about what went wrong. The error ErrUnsupportedNetwork is returned when an unsupported network is specified.

```go
var ErrUnsupportedNetwork = errors.New(
    "unsupported network: the specified network is not recognized. Please ensure that the network name is correct and supported by the application."
    )
```

## Contribute

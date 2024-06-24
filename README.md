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

### Generate Mnemonic

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
- Output
```
Mnemonic: 
```

## Error Handling

Errors in the interface are returned in Go's idiomatic way as the second return value. The error messages provide detailed information about what went wrong. The error ErrUnsupportedNetwork is returned when an unsupported network is specified.

```go
var ErrUnsupportedNetwork = errors.New(
    "unsupported network: the specified network is not recognized. Please ensure that the network name is correct and supported by the application."
    )
```

## Contribute

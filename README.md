# Multichain Wallet (MCW)

MCW is a Go package that provides a unified interface for managing wallets, generating mnemonics, and interacting with different blockchain networks: Ethereum, Solana, Bitcoin, and Aptos.The interface includes functionality for creating and managing wallets, handling transactions, and performing other blockchain-related operations.

## Installation

go get ...

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

## Error Handling

Errors in the interface are returned in Go's idiomatic way as the second return value. The error messages provide detailed information about what went wrong. The error ErrUnsupportedNetwork is returned when an unsupported network is specified.

```go
var ErrUnsupportedNetwork = errors.New("unsupported network: the specified network is not recognized. Please ensure that the network name is correct and supported by the application.")
```

## Contribute

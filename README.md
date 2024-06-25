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

`WalletFromMnemonic` generates a wallet for a specified network using a given mnemonic phrase and passphrase. It takes in mnemonic, passphrase and network in a `types.WalletParam` struct.

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

- **Output**:

```go
    Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about,
    PrivateKey: 5e62984d8bda6a40bbdb08496b1d3f6f5e1be8b1fe4a575d18b9e0f5934eac4d,
    PublicKey: 0360ec40d4ec3132b3c5d6d9b4cddf8e17bb2c0e9e20d69e2e0bb9f9d7f9d20d6f,
    Address: 0x1234567890123456789012345678901234567890
```

### CreateWallet

`CreateWallet` generates a new wallet for a specified network. It takes in network and other parameters in a `types.CWParam` struct. It returns a Wallet struct containing the mnemonic, private key, public key, and address.

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

### GetAddressFromPrivateKey

`GetAddressFromPrivateKey` derives the address from a given private key for a specified network. It takes in the network and private key as strings. It returns an Address struct.
It supports Ethereum, Solana, Bitcoin,and Aptos. There is no Flow support because Flow addresses aren't derived from private or public keys. In Flow, addresses are assigned by the network when an account is created.

```go
network := "ethereum"
privateKey := "5e62984d8bda6a40bbdb08496b1d3f6f5e1be8b1fe4a575d18b9e0f5934eac4d"
address, err := wallet.GetAddressFromPrivateKey(network, privateKey)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Address:", address)
}
```

- **Output**

```go
Address: {
    Address: "0x1234567890123456789012345678901234567890"
}
```

> **Note:** The actual address output will vary depending on the network and private key provided. Each supported blockchain (Ethereum, Solana, Bitcoin, and Aptos) has its own method of deriving addresses from private keys:

- Ethereum: Addresses are derived from the public key, which is in turn derived from the private key.
- Solana: Addresses are essentially the public key in base58 encoding.
- Bitcoin: Addresses are derived from the public key and can be in different formats (e.g., P2PKH, P2SH, Bech32).
- Aptos: Addresses are derived from the public key.

For Flow, addresses are assigned by the network when an account is created, not derived from keys. This is why the function doesn't support Flow addresses.

### GetBalance

`GetBalance` retrieves the balance for a given address on a specified network. It takes in network, address, and other parameters in a `types.BalanceParam` struct. It returns a `Balance` struct.
It supports Ethereum, Solana, Bitcoin, Aptos, and Flow.

```go
bp := types.BalanceParam{
    Network: "ethereum",
    Address: "0x1234567890123456789012345678901234567890",
    EndpointURL: "http://dummy-ethereum-rpc.com:8545" // replace with your EndpointURL
    // Add other necessary parameters
}
balance, err := wallet.GetBalance(bp)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Balance:", balance)
}
```

- **Output**

```go
Balance: {
    Address: 0x1234567890123456789012345678901234567890
    Balance: "1000000000000000000",  // 1 ETH in wei
}
```

### GetTokenBalance

`GetTokenBalance` retrieves the token balance for a given address and token on a specified network. It takes in network, address, token address, and other parameters in a `types.TBParam` struct. It returns a `TokenBalance` struct.
It supports Ethereum, Solana, and Aptos. There is no Flow and Bitcoin support yet.

```go
tbp := types.TBParam{
    Network: "solana",
    EndpointURL: "rpc.MainnetRPCEndpoint"
    Address: "GLHCm5rMasb1kX7M7QL6Q9SVRWPscXsXpw32bmYgT7xo",
    TokenAddress: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  // USDC token address
    Context: context.TODO()
    // Add other necessary parameters
}
tokenBalance, err := wallet.GetTokenBalance(tbp)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Token Balance:", tokenBalance)
}
```

- **Output**

```go
Token Balance: {
    Address: GLHCm5rMasb1kX7M7QL6Q9SVRWPscXsXpw32bmYgT7xo
    Data: 58.90
}
```

### GetTxByHash

`GetTxByHash` retrieves transaction details for a given transaction hash on a specified network. It takes in network, transaction hash, and other parameters in a `types.HashParam` struct. It returns a `TransactionByHash` struct.
It supports Ethereum, Solana, Bitcoin, Aptos, and Flow.

```go
hp := types.HashParam{
    Network: "ethereum",
    Hash: "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234",
    // Add other necessary parameters
}
tx, err := wallet.GetTxByHash(hp)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Transaction:", tx)
}
```

- **Output**

```go
Transaction: {
    isPending: false,
    Transaction: {

    }
}
```

### Transfer

`Transfer` initiates a transfer of native currency on a specified network. It takes in network, from address, to address, amount, and other parameters in a `types.TransferParam` struct. It returns a `TransferData` struct.
It supports Ethereum, Solana, Bitcoin, Aptos, and Flow.

```go
tp := types.TransferParam{
    Network: "ethereum",
    From: "0x1234567890123456789012345678901234567890",
    To: "0x0987654321098765432109876543210987654321",
    Amount: "1000000000000000000",  // 1 ETH in wei
    // Add other necessary parameters
    }
    transferData, err := wallet.Transfer(tp)
    if err != nil {
        fmt.Println("Error:", err)
    } else {
        fmt.Println("Transfer Data:", transferData)
    }
```

- **Output**

```go
ash: 0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234,
Data: {

}
```

### TransferToken

`TransferToken` initiates a transfer of tokens on a specified network. It takes in network, from address, to address, token address, amount, and other parameters in a `types.TransferTokenParam` struct. It returns a `TransferData` struct.
It supports only Ethereum and Solana. There is no Bitcoin, Aptos, and Flow support yet.

```go
ttp := types.TransferTokenParam{
    Network: "ethereum",
    From: "0x1234567890123456789012345678901234567890",
    To: "0x0987654321098765432109876543210987654321",
    TokenAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  // USDC token address
    Amount: "1000000",
    // Add other necessary parameters
}
transferData, err := wallet.TransferToken(ttp)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Transfer Data:", transferData)
}
```

- **Output**

```go
Transfer Data: {
    TxHash: "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234",
    Data: {

    }
    // Other transfer details
}
```

### GetTokenInfo

`GetTokenInfo` retrieves information about a token on a specified network. It takes in network, token address, and other parameters in a `types.TokenInfoParam` struct. It returns a `TokenInfo` struct.
It supports only Ethereum and Solana. There is no Bitcoin, Aptos, and Flow support yet.

```go
tip := types.TokenInfoParam{
    Network: "ethereum",
    TokenAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  // USDC token address
    // Add other necessary parameters
}
tokenInfo, err := wallet.GetTokenInfo(tip)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Token Info:", tokenInfo)
}
```

- **Output**

```go
Token Info: {
    Name: "USD Coin",
    Symbol: "USDC",
    Decimals: 6,
    TotalSupply: "1000000000000000",
    // Other token details
}
```

### SmartContractCall

SmartContractCall executes a smart contract function on a specified network. It takes in network, contract address, function name, parameters, and other details in a types.SmartContractCallPayload struct. It returns an interface{} which can be type-asserted to the expected return type.
It supports only Ethereum at the moment.

```go
payload := types.SmartContractCallPayload{
    Network: "ethereum",
    ContractAddress: "0x1234567890123456789012345678901234567890",
    FunctionName: "balanceOf",
    Params: []interface{}{"0x0987654321098765432109876543210987654321"},
    // Add other necessary parameters
}
result, err := wallet.SmartContractCall(payload)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Result:", result)
}
```

- **Output**

```go
Result: 1000000000000000000
```

### CreateAccountCreationTx

CreateAccountCreationTx prepares a transaction to create a new Flow account and calculates the expected address for this account. It takes in a wallet, payer address, and network. It returns a pointer to the prepared transaction, the expected address of the new account, and an error if any.

This function is specific to the Flow blockchain.

> **Note:** This function only prepares the transaction and calculates the expected address. The transaction still needs to be signed and submitted to the blockchain to actually create the account.

```go
wallet := types.Wallet{
    PublicKey: "0360ec40d4ec3132b3c5d6d9b4cddf8e17bb2c0e9e20d69e2e0bb9f9d7f9d20d6f",
    // Other wallet details
}
payer := Flow.HexToAddress("0x1234567890123456")
network := Flow.Mainnet

tx, expectedAddress, err := wallet.CreateAccountCreationTx(wallet, payer, network)
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Transaction:", tx)
    fmt.Println("Expected Address:", expectedAddress)
}
```

- **Output**

```go
Transaction: {...}  // Flow transaction object
Expected Address: 0x9876543210987654
```

## Error Handling

Errors in the interface are returned in Go's idiomatic way as the second return value. The error messages provide detailed information about what went wrong. The error ErrUnsupportedNetwork is returned when an unsupported network is specified.

```go
var ErrUnsupportedNetwork = errors.New(
    "unsupported network: the specified network is not recognized. Please ensure that the network name is correct and supported by the application."
    )
```

## Contribute

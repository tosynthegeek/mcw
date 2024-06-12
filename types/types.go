package types

import (
	"math/big"
)

// Wallet contains the mnemonic, private key, public key and address.
type Wallet struct {
	Mnemonic   string
	PrivateKey string
	PublicKey  string
	Address    string
}

type Address struct {
	Address    string
	PrivateKey string
}

type Balance struct {
	Address 		string
	Balance			big.Int
	TokenAddress 	*string
}


type BalancePayload struct {
	Address 		string
	RpcUrl 			string
	Network 		*string
	TokenAddress 	string
	ABI				[]byte
}

type TransferETHPayload struct{
	PrivateKey		string
	RpcUrl 			string
	Recipient		string
	Amount			big.Int
	GasPrice		*big.Int
	GasLimit		*uint64
	Nonce			*uint64
	Network			*string
}

type TransferTokenPayload struct{
	PrivateKey		string
	RpcUrl 			string
	Recipient		string
	TokenAddress	string
	Amount			big.Int
	GasPrice		*big.Int
	GasLimit		*uint64
	Nonce			*uint64
	Network			*string
}

type TransferData struct {
	Hash        string  // Transaction hash
    FromAddress string  // Sender's address
    ToAddress   string  // Recipient's address
    Amount      *big.Int // Amount transferred
    GasLimit     uint64   // Gas used for the transaction
    GasPrice    *big.Int // Gas price used
    BlockNumber uint64
}

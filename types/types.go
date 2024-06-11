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
	Network 		string
	TokenAddress 	string
	ABI				[]byte
}


package types

import (
	"context"
	"math/big"

	"github.com/blocto/solana-go-sdk/common"
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

type TokenInfoPayload struct {
	RpcUrl 			string
	TokenAddress 	string
	ABI				[]byte
}

type TokenInfo struct {
	Name 			string
	Symbol			string
	Decimals		uint8
	TotalSupply		big.Int
	TokenAddress	string
}

type SmartContractCallPayload struct {
	PrivateKey   string
	RpcUrl       string
	ContractAddr string
	Method       string
	Params       []interface{}
	ABI          []byte
}

type TransferSolPayload struct{
	Context			context.Context				
	PrivateKey		string
	RpcUrl 			string
	Recipient		string
	Amount			uint64 // In Lamports 
	Network			*string
}

type TransferSolTokenPayload struct{
	Context			context.Context	
	PrivateKey		string
	RpcUrl 			string
	Recipient		string
	Mint			string
	Amount			uint64 // In Lamports 
	Network			*string
}

type TokenMetaData struct {
	Name 		string
	Symbol		string
	URL			string
}

type SolTokenInfo struct {
	Name            	string
	Symbol          	string
	URL             	string
	Supply          	uint64
	Mint				common.PublicKey
	Decimals        	uint8
	Amount				uint64
	Owner           	common.PublicKey
	MintAuthority   	common.PublicKey
	FreezeAuthority 	common.PublicKey
	IsInitialize	   	bool
	AssociatedAccount 	string
}
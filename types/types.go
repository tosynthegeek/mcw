package types

import (
	"context"
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/blocto/solana-go-sdk/common"
	"github.com/btcsuite/btcd/chaincfg"
	Flow "github.com/onflow/flow-go-sdk"
)

type Blockchain interface {
    WalletFromMnemonic(wp WalletParam) (Wallet, error)
	CreateWallet(cwp CWParam) (Wallet, error)
    GetAddressFromPrivateKey(privateKey string) (Address, error)
    GetBalance(bp BalanceParam) (Balance, error)
    GetTokenBalance(tbp TBParam) (TokenBalance, error)
    GetTxByHash(hp HashParam) (TransactionByHash, error)
    Transfer(tp TransferParam) (TransferData, error)
    TransferToken(ttp TransferTokenParam) (TransferData, error)
    GetTokenInfo(tip TokenInfoParam) (TokenInfo, error)
	SmartContractCall(payload SmartContractCallPayload) ([]interface{}, error)
}

// Wallet contains the mnemonic, private key, public key and address.
type Wallet struct {
	Mnemonic   string
	PrivateKey string
	PublicKey  string
	Address    string
}

type WalletParam struct {
	Mnemonic		string
	Passphrase 		string
	Network 		string
}

type CWParam struct{
	Passphrase 		string
	Network 		string
}

type Address struct {
	Address    string
	PrivateKey string
}

type Balance struct {
	Address 		string
	Balance			string
	Data			interface{}
}

type BalanceParam struct {
	Address 		string // address for sol, eth, btc
	EndpointURL		string // endpoint for sol, rpcurl for eth
	Network 		string // "ethereum", "bitcoin", "solana", "aptos"
	Context 		context.Context
	AptosConfig		aptos.NetworkConfig
	BtcConfig		BtcClientConfig
	AptosAddress  	aptos.AccountAddress //types.AccountAddress for aptos
}

type BtcClientConfig struct {
	Host			string // Host is the IP address and port of the RPC server you want to connect to
	User       		string // User is the username to use to authenticate to the RPC server.
	Pass       		string // Pass is the passphrase to use to authenticate to the RPC server.
	ChainParams 	*chaincfg.Params
	UseTLS     		bool   // Whether to use the transport layer security
	CertPath   		string // Path to TLS certificate, if UseTLS is true
	Proxy      		string
	ProxyUser  		string
	ProxyPass  		string
	ExtraHeaders 	map[string]string
}

type TBParam struct {
	Address 		string
	EndpointURL		string
	Network 		string
	Context 		context.Context
	TokenAddress 	string // Mint address for solana
	AptosConfig		aptos.NetworkConfig
	AptosAddress  	aptos.AccountAddress //types.AccountAddress for aptos
	ABI				[]byte
}


type TokenBalance struct {
	Address 		string
	Balance			big.Int
	TokenAddress 	*string
	Data			interface{}
}

type HashParam struct {
	Hash 		string // address for sol, eth, btc
	EndpointURL		string // endpoint for sol, rpcurl for eth
	Network 		string // "ethereum", "bitcoin", "solana", "aptos"
	Context 		context.Context
	AptosConfig		aptos.NetworkConfig
	BtcConfig		BtcClientConfig
}

type TransactionByHash struct {
	Pending			bool
	Transaction		interface{}
}
type TransferParam struct {
	PrivateKey		string
	Sender 			string
	FlowSender		Flow.Address
	EndpointURL		string
	Recipient		string
	FlowRecipient	Flow.Address
	AptosRecipient  aptos.AccountAddress //types.AccountAddress for aptos
	Amount			uint64
	GasPrice		*big.Int
	GasLimit		*uint64
	Nonce			*uint64
	Network			string

	// Config
	Context 		context.Context
	AptosConfig		aptos.NetworkConfig
	BtcConfig		BtcClientConfig
	Script			[]byte
}

type TransferData struct {
	Hash        string  // Transaction hash
	Data		interface{}
}
type TransferTokenParam struct{
	PrivateKey		string
	EndpointURL		string
	Recipient		string
	Token 			string // Token address for eth and Mint for Solana
	Amount			uint64
	GasPrice		*big.Int //eth
	GasLimit		*uint64 //eth
	Nonce			*uint64 //eth
	Network			string

	Context			context.Context // sol
}

type TokenInfoParam struct {
	EndpointURL		string
	TokenAddress 	string
	ABI				[]byte

	Context			context.Context // sol
	Network 		string
}

type TokenInfo struct {
	Name 			string
	Symbol			string
	Decimals		uint8
	Supply			big.Int
	TokenAddress	string

	// Additional for SOL Token Info
	URL             	string
	Mint				common.PublicKey
	Owner           	common.PublicKey
	MintAuthority   	common.PublicKey
	FreezeAuthority 	common.PublicKey
	IsInitialize	   	bool
	AssociatedAccount 	string
}

type SmartContractCallPayload struct {
	PrivateKey   	string
	RpcUrl       	string
	ContractAddr 	string
	Method       	string
	Params       	[]interface{}
	ABI          	[]byte
	Network 		string
}

type TokenMetaData struct {
	Name 		string
	Symbol		string
	URL			string
}
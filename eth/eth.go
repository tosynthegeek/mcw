package eth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"mcw/client"
	types "mcw/types"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// WalletFromMnemonic generates an Ethereum wallet from a given mnemonic and passphrase (password).
// It returns a Wallet struct containing the mnemonic, private key, public key, and address.
func WalletFromMnemonic(mnemonic string, passphrase string) types.Wallet {

    // Verify that the provided mnemonic is valid.  
    // Validity is determined by both the number of words being appropriate, and that all the words in the mnemonic are present in the word list.
    if !bip39.IsMnemonicValid(mnemonic) {
        log.Fatal("Mnemonic is not valid")
    }

    // Generate seed from mnemonic and passphrase
    seed := bip39.NewSeed(mnemonic, passphrase)
    
    // Generate master key from seed
    masterKey, err := bip32.NewMasterKey(seed)
    if err != nil {
        log.Fatal(err.Error())
    }

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
    key := addressIndex.Key
    ecdsaKey, err:= crypto.ToECDSA(key)
    if err != nil {
        log.Fatal(err.Error())
    }
    bytesKey:= crypto.FromECDSA(ecdsaKey)
    privateKey:= hexutil.Encode(bytesKey)[2:]

    publicKeyCrypto := ecdsaKey.Public()
    publicKeyEcdsa, ok:= publicKeyCrypto.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal(err.Error())
    }

    publicKeyBytes := crypto.FromECDSAPub(publicKeyEcdsa)
    publicKey:= hexutil.Encode(publicKeyBytes)[4:]
    address:= crypto.PubkeyToAddress(*publicKeyEcdsa).Hex()

    wallet:= types.Wallet {
        Mnemonic:   mnemonic,
        PrivateKey: privateKey,
        PublicKey:  publicKey,
        Address:    address,
    }
    return wallet
}

// CreateWallet generates a wallet from a given passphrase (password),
// and returns a Wallet struct containing the mnemonic, private key, public key, and Ethereum address.
func CreateWallet(passphrase string) types.Wallet {
    entropy, err:= bip39.NewEntropy(128) // 12 words
    if err != nil {
        log.Fatal(err.Error())
    }
    mnemonic, err:= bip39.NewMnemonic(entropy)
    if err != nil {
        log.Fatal(err.Error())
    }
    
    wallet:= WalletFromMnemonic(mnemonic, passphrase)

    return wallet
}

// Get address from Private Key
func GetAddressFromPrivKateKey(privateKey string) types.Address {
    privKeyBytes, err := hex.DecodeString(privateKey)
    if err != nil {
        fmt.Println("Error Decoding Private Key: ", err)
    }

    privateKeyECDSA, err := crypto.ToECDSA(privKeyBytes)
    if err != nil {
        fmt.Println("Error: ", err)
    }

    publicKeyCrypto := privateKeyECDSA.Public()
    publicKeyEcdsa, ok:= publicKeyCrypto.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal(err.Error())
    }
    address:= crypto.PubkeyToAddress(*publicKeyEcdsa).Hex()
    
    return types.Address{
        Address: address,
        PrivateKey: privateKey,
    }
}
// decimal

// GetEthBalance checks for the ETH balance of an address
// It returns a Balance struct containing the address,  balance (in wei) and the network
func GetEthBalance(rpcUrl string, address string) types.Balance {
    client:= client.EthClient(rpcUrl)
    account:= common.HexToAddress(address)
    balance, err:= client.BalanceAt(context.Background(), account, nil)
    if err != nil {
        log.Fatal(err.Error())
    }

    return types.Balance{
        Address: address,
        Balance: *balance,
    }
}

// GetTokenBalance checks for the balance of an ERC20 token for an address.
// It takes in struct as argument `balancePayload` containing address, rpc url, network and contract address of the ERC 20 token.
// It returns a Balance struct containing the address,  balance (in wei) and the network
func GetTokenBalance(balancePayload types.BalancePayload) types.Balance {
    client:= client.EthClient(balancePayload.RpcUrl)
    account:= common.HexToAddress(balancePayload.Address)
    tokenAddress:= common.HexToAddress(balancePayload.TokenAddress)
    abiData, err:= JsonToABI(balancePayload.ABI)    
    if err != nil {
        fmt.Println(err.Error())
    }

    contract:= bind.NewBoundContract(tokenAddress, abiData, client, client, client)
    
    var balance *big.Int
    result:= []interface{}{&balance}
	callOpts:= &bind.CallOpts{}
    
	err = contract.Call(callOpts, &result, "balanceOf", account)
	if err != nil {
		log.Fatal("failed to call balanceOf function: ", err)
	}

    return types.Balance{
		Address:        balancePayload.Address,
		Balance:        *balance,  
		TokenAddress:   &balancePayload.TokenAddress, // assuming `types.Balance` has an `Amount` field of type `*big.Int`
	}
}

//JsonToABI converts imported ABI in JSON into type abi.ABI
func JsonToABI(abiData []byte) (abi.ABI, error) {
    parsedABI, err := abi.JSON(bytes.NewReader(abiData))
	if err != nil {
		log.Fatal("failed to parse ABI: ", err)
	}

    return parsedABI, nil
}

// GetTxByHash retrieves the transaction and its pending status given its hash and an RPC URL.
// It returns the transaction object and a boolean indicating whether the transaction is pending.
func GetTxByHash(hash string, rpcUrl string) (*ethTypes.Transaction, bool ){
    client:= client.EthClient(rpcUrl)
    txHash:= common.HexToHash(hash)
    tx, isPending, err:= client.TransactionByHash(context.Background(), txHash)
    if err != nil {
        log.Fatal(err.Error())
    }

    return tx, isPending
}

// TransferETH sends ETH from one wallet to  a specified recipient address. 
// It returns the transaction hash, sender address, recipient address, amount transferred and transaction info like gas limit, gas price and block number.
func TransferETH(transferPayload types.TransferETHPayload) (types.TransferData) {
    client:= client.EthClient(transferPayload.RpcUrl)
    
    var gasPrice    *big.Int
    var gasLimit    uint64
    var nonce       uint64
    var err         error

    recipient:= common.HexToAddress(transferPayload.Recipient)

    privateKey, err:= crypto.HexToECDSA(transferPayload.PrivateKey)
    if err != nil {
        log.Fatal(err.Error())
    }
    publicKey:= privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal("error casting public key to ECDSA")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    if transferPayload.GasPrice == nil {
        gasPrice, err = client.SuggestGasPrice(context.Background())
        if err != nil {
           log.Fatal(err.Error())
        }
    } else {
        gasPrice = transferPayload.GasPrice
    }

    if transferPayload.GasLimit == nil {
        gasLimit = uint64(21000)
    } else {
        gasLimit = *transferPayload.GasLimit
    }
    
    if transferPayload.Nonce == nil {
        nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
        if err != nil {
            log.Fatal(err.Error())
        }
    } else {
        nonce = *transferPayload.Nonce
    }

    tx:= ethTypes.NewTransaction(nonce, recipient, &transferPayload.Amount, gasLimit, gasPrice, nil)
    chainID, err:= client.NetworkID(context.Background())
    if err != nil {
        log.Fatal(err.Error())
    }

    signedTx, err:= ethTypes.SignTx(tx, ethTypes.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        log.Fatal(err.Error())
    }

    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        log.Fatal(err)
    }

    reciept, err:= bind.WaitMined(context.Background(), client, signedTx)
    if err != nil {
        log.Fatal(err.Error())
    }

    return types.TransferData{
        Hash: signedTx.Hash().Hex(),
        FromAddress: fromAddress.Hex(),
        ToAddress: transferPayload.Recipient,
        Amount: &transferPayload.Amount,
        GasLimit: gasLimit,
        GasPrice: gasPrice,
        BlockNumber: reciept.BlockNumber.Uint64(),
    }
}

// TransferToken sends tokens from a wallet to a specified recipient address.
// It returns the transaction hash, sender address, recipient address, amount transferred and transaction info like gas limit, gas price and block number.
func TransferToken(transferPayload types.TransferTokenPayload) types.TransferData {
    var gasPrice    *big.Int
    var gasLimit    uint64
    var nonce       uint64
    var err         error

    client:= client.EthClient(transferPayload.RpcUrl)
    recipient:= common.HexToAddress(transferPayload.Recipient)
    tokenAddress:= common.HexToAddress(transferPayload.TokenAddress)

    privateKey, err:= crypto.HexToECDSA(transferPayload.PrivateKey)
    if err != nil {
        log.Fatal(err.Error())
    }
    publicKey:= privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal("error casting public key to ECDSA")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    
    signature:= []byte("transfer(address,uint256)")
    hash:= sha3.NewLegacyKeccak256()
    hash.Write(signature)
    methodID:= hash.Sum(nil)[:4]
    paddedAddress := common.LeftPadBytes(recipient.Bytes(), 32)
    paddedAmount := common.LeftPadBytes(transferPayload.Amount.Bytes(), 32)

    var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddress...)
    data = append(data, paddedAmount...)

    if transferPayload.GasPrice == nil {
        gasPrice, err = client.SuggestGasPrice(context.Background())
        if err != nil {
           log.Fatal(err.Error())
        }
    } else {
        gasPrice = transferPayload.GasPrice
    }

    if transferPayload.GasLimit == nil {
        gasLimit, err = client.EstimateGas(context.Background(), ethereum.CallMsg{
            To: &recipient,
            Data: data,
        })
        if err != nil {
            log.Fatal(err.Error())
        }
    } else {
        gasLimit = *transferPayload.GasLimit
    }
    
    if transferPayload.Nonce == nil {
        nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
        if err != nil {
            log.Fatal(err.Error())
        }
    } else {
        nonce = *transferPayload.Nonce
    }


    tx:= ethTypes.NewTransaction(nonce, tokenAddress, &transferPayload.Amount, gasLimit, gasPrice, data)
    chainID,err:= client.ChainID(context.Background())
    if err != nil {
        log.Fatal(err.Error())
    }

    signedTx, err:= ethTypes.SignTx(tx, ethTypes.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        log.Fatal(err.Error())
    }

    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        log.Fatal(err.Error())
    }
    
    reciept, err:= bind.WaitMined(context.Background(), client, signedTx)
    if err != nil {
        log.Fatal(err.Error())
    }

    return types.TransferData{
        Hash: signedTx.Hash().Hex(),
        FromAddress: fromAddress.Hex(),
        ToAddress: transferPayload.Recipient,
        Amount: &transferPayload.Amount,
        GasLimit: gasLimit,
        GasPrice: gasPrice,
        BlockNumber: reciept.BlockNumber.Uint64(),
    }
}

// Get Token Info provides the name, symbol, decimals, token supply and token address of a token.
func GetTokenInfo(tokenInfoPayload types.TokenInfoPayload) types.TokenInfo {
    client:= client.EthClient(tokenInfoPayload.RpcUrl)
    tokenAddress:= common.HexToAddress(tokenInfoPayload.TokenAddress)
    abiData, err:= JsonToABI(tokenInfoPayload.ABI)    
    if err != nil {
        fmt.Println(err.Error())
    }

    contract:= bind.NewBoundContract(tokenAddress, abiData, client, client, client)

    // Variables to hold token info
    var name, symbol string
    var decimals uint8
    var totalSupply *big.Int = new(big.Int)

    // Prepare result slices
    var resultName []interface{}
    var resultSymbol []interface{}
    var resultDecimals []interface{}
    var resultTotalSupply []interface{}

    // Call contract methods
    err = contract.Call(nil, &resultName, "name")
    if err != nil {
        fmt.Println("Failed to fetch token name:", err)
    } else if len(resultName) > 0 {
        name = resultName[0].(string)
    }

    err = contract.Call(nil, &resultSymbol, "symbol")
    if err != nil {
        fmt.Println("Failed to fetch token symbol:", err)
    } else if len(resultSymbol) > 0 {
        symbol = resultSymbol[0].(string)
    }

    err = contract.Call(nil, &resultDecimals, "decimals")
    if err != nil {
        fmt.Println("Failed to fetch token decimals:", err)
    } else if len(resultDecimals) > 0 {
        decimals = resultDecimals[0].(uint8)
    }

    err = contract.Call(nil, &resultTotalSupply, "totalSupply")
    if err != nil {
        fmt.Println("Failed to fetch total supply:", err)
    } else if len(resultTotalSupply) > 0 {
        totalSupply = resultTotalSupply[0].(*big.Int)
    }

    return types.TokenInfo{
        Name: name,
        Symbol: symbol,
        Decimals: decimals,
        TotalSupply: *totalSupply,
        TokenAddress: tokenInfoPayload.TokenAddress,
    }
}

// SmartContractCalls performs a generic method call on a specified smart contract.
// It accepts the contract address, method name, parameters, and ABI, and returns the method results.
func SmartContractCalls(payload types.SmartContractCallPayload) ([]interface{}, error) {
	client, err := ethclient.Dial(payload.RpcUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}

	parsedABI, err := abi.JSON(bytes.NewReader(payload.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	contract := bind.NewBoundContract(common.HexToAddress(payload.ContractAddr), parsedABI, client, client, client)

	callOpts := &bind.CallOpts{}
	var result []interface{}
	err = contract.Call(callOpts, &result, payload.Method, payload.Params...)
	if err != nil {
		return nil, fmt.Errorf("failed to call contract method: %w", err)
	}

	return result, nil
}


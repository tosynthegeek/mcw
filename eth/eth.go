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
func WalletFromMnemonic(mnemonic string, passphrase string) (types.Wallet, error) {

    // Verify that the provided mnemonic is valid.  
    // Validity is determined by both the number of words being appropriate, and that all the words in the mnemonic are present in the word list.
    if !bip39.IsMnemonicValid(mnemonic) {
        fmt.Errorf("Mnemonic is not valid")
    }

    // Generate seed from mnemonic and passphrase
    seed := bip39.NewSeed(mnemonic, passphrase)
    
    // Generate master key from seed
    masterKey, err := bip32.NewMasterKey(seed)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to create master key: %w", err)
    }

    // Use BIP-44 derivation path for Ethereum: m/44'/60'/0'/0/0
    purpose, err := masterKey.NewChildKey(44)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive purpose key: %w", err)
    }

    coinType, err := purpose.NewChildKey(60)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive coin type key: %w", err)
    }

    account, err := coinType.NewChildKey(0)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive account key: %w", err)
    }

    change, err := account.NewChildKey(0)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive change key: %w", err)
    }

    addressIndex, err := change.NewChildKey(0)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("failed to derive address index: %w", err)
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
    return wallet, nil
}

// CreateWallet generates a wallet from a given passphrase (password),
// and returns a Wallet struct containing the mnemonic, private key, public key, and Ethereum address.
func CreateWallet(passphrase string) (types.Wallet, error){
    entropy, err:= bip39.NewEntropy(128) // 12 words
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error generating entropy: %w", err)
    }
    mnemonic, err:= bip39.NewMnemonic(entropy)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error creating mnemonic: %w", err)
    }
    
    wallet, err:= WalletFromMnemonic(mnemonic, passphrase)
    if err != nil {
        return types.Wallet{}, fmt.Errorf("error creating mnemonic: %w", err)
    }

    return wallet, nil
}

// Get address from Private Key
func GetAddressFromPrivKateKey(privateKey string) (types.Address, error) {
    privKeyBytes, err := hex.DecodeString(privateKey)
    if err != nil {
        return types.Address{}, fmt.Errorf("error Decoding Private Key: ", err)
    }

    privateKeyECDSA, err := crypto.ToECDSA(privKeyBytes)
    if err != nil {
        return types.Address{}, fmt.Errorf("error creating ecdsa private key: ", err)
    }

    publicKeyCrypto := privateKeyECDSA.Public()
    publicKeyEcdsa, ok:= publicKeyCrypto.(*ecdsa.PublicKey)
    if !ok {
        return types.Address{}, fmt.Errorf("error getting public key: %w", err)
    }
    address:= crypto.PubkeyToAddress(*publicKeyEcdsa).Hex()
    
    return types.Address{
        Address: address,
        PrivateKey: privateKey,
    }, nil
}
// decimal

// GetBalance checks for the balance of the native network token of an address
// It returns a Balance struct containing the address,  balance (in wei) and the network
func GetBalance(bp types.BalanceParam) (types.Balance, error) {
    client:= client.EthClient(bp.EndpointURL)
    account:= common.HexToAddress(bp.Address)
    balance, err:= client.BalanceAt(context.Background(), account, nil)
    if err != nil {
        log.Fatal(err.Error())
    }

    return types.Balance{
        Address: bp.Address,
        Balance: balance.String(),
    }, nil
}

// GetTokenBalance checks for the balance of an ERC20 token for an address.
// It takes in struct as argument `balancePayload` containing address, rpc url, network and contract address of the ERC 20 token.
// It returns a Balance struct containing the address,  balance (in wei) and the network
func GetTokenBalance(tbp types.TBParam) (types.TokenBalance, error) {
    client:= client.EthClient(tbp.EndpointURL)
    account:= common.HexToAddress(tbp.Address)
    tokenAddress:= common.HexToAddress(tbp.TokenAddress)
    abiData, err:= JsonToABI(tbp.ABI)    
    if err != nil {
        return types.TokenBalance{}, fmt.Errorf("error importing ABI: %w", err)
    }

    contract:= bind.NewBoundContract(tokenAddress, abiData, client, client, client)
    
    var balance *big.Int
    result:= []interface{}{&balance}
	callOpts:= &bind.CallOpts{}
    
	err = contract.Call(callOpts, &result, "balanceOf", account)
	if err != nil {
		return types.TokenBalance{}, fmt.Errorf("error getting balance: %w", err)
	}

    return types.TokenBalance{
		Address:        tbp.Address,
		Balance:        *balance,  
		TokenAddress:   &tbp.TokenAddress, // assuming `types.Balance` has an `Amount` field of type `*big.Int`
	}, nil
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
func GetTxByHash(hp types.HashParam) (types.TransactionByHash, error ){
    client:= client.EthClient(hp.EndpointURL)
    txHash:= common.HexToHash(hp.Hash)
    tx, isPending, err:= client.TransactionByHash(context.Background(), txHash)
    if err != nil {
        return types.TransactionByHash{}, fmt.Errorf("error fetting transaction: %w", err)
    }

    return types.TransactionByHash{
        Pending: isPending,
        Transaction: tx,
    }, nil
}

// TransferETH sends ETH from one wallet to  a specified recipient address. 
// It returns the transaction hash, sender address, recipient address, amount transferred and transaction info like gas limit, gas price and block number.
func Transfer(tp types.TransferParam) (types.TransferData, error) {
    client:= client.EthClient(tp.EndpointURL)
    amount:= new(big.Int).SetUint64(tp.Amount)
    
    var gasPrice    *big.Int
    var gasLimit    uint64
    var nonce       uint64
    var err         error

    recipient:= common.HexToAddress(tp.Recipient)

    privateKey, err:= crypto.HexToECDSA(tp.PrivateKey)
    if err != nil {
        log.Fatal(err.Error())
    }
    publicKey:= privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        return types.TransferData{}, fmt.Errorf("error casting public key to ECDSA")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    if tp.GasPrice == nil {
        gasPrice, err = client.SuggestGasPrice(context.Background())
        if err != nil {
           return types.TransferData{}, fmt.Errorf("error getting gas price: %w", err)
        }
    } else {
        gasPrice = tp.GasPrice
    }

    if tp.GasLimit == nil {
        gasLimit = uint64(21000)
    } else {
        gasLimit = *tp.GasLimit
    }
    
    if tp.Nonce == nil {
        nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
        if err != nil {
            return types.TransferData{}, fmt.Errorf("error getting nonce: %w", err)
        }
    } else {
        nonce = *tp.Nonce
    }

    tx:= ethTypes.NewTransaction(nonce, recipient, amount, gasLimit, gasPrice, nil)
    chainID, err:= client.NetworkID(context.Background())
    if err != nil {
        return types.TransferData{}, fmt.Errorf("error creating new transaction: %w", err)
    }

    signedTx, err:= ethTypes.SignTx(tx, ethTypes.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("error signing transaction: %w", err)
    }

    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("error sending transaction: %w", err)
    }

    reciept, err:= bind.WaitMined(context.Background(), client, signedTx)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("error mining transaction: %w", err)
    }

    return types.TransferData{
        Hash: signedTx.Hash().Hex(),
        Data: reciept,
    }, nil
}

// TransferToken sends tokens from a wallet to a specified recipient address.
// It returns the transaction hash, sender address, recipient address, amount transferred and transaction info like gas limit, gas price and block number.
func TransferToken(ttp types.TransferTokenParam) (types.TransferData, error) {
    var gasPrice    *big.Int
    var gasLimit    uint64
    var nonce       uint64
    var err         error

    amount:= new(big.Int).SetUint64(ttp.Amount)

    client:= client.EthClient(ttp.EndpointURL)
    recipient:= common.HexToAddress(ttp.Recipient)
    tokenAddress:= common.HexToAddress(ttp.Token)

    privateKey, err:= crypto.HexToECDSA(ttp.PrivateKey)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("error parsing private key: %w", err)
    }
    publicKey:= privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        return types.TransferData{}, fmt.Errorf("error casting public key to ECDSA")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    
    signature:= []byte("transfer(address,uint256)")
    hash:= sha3.NewLegacyKeccak256()
    hash.Write(signature)
    methodID:= hash.Sum(nil)[:4]
    paddedAddress := common.LeftPadBytes(recipient.Bytes(), 32)
    paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)

    var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddress...)
    data = append(data, paddedAmount...)

    if ttp.GasPrice == nil {
        gasPrice, err = client.SuggestGasPrice(context.Background())
        if err != nil {
           return types.TransferData{}, fmt.Errorf("error getting gas price: %w", err)
        }
    } else {
        gasPrice = ttp.GasPrice
    }

    if ttp.GasLimit == nil {
        gasLimit, err = client.EstimateGas(context.Background(), ethereum.CallMsg{
            To: &recipient,
            Data: data,
        })
        if err != nil {
            return types.TransferData{}, fmt.Errorf("error getting gas limit: %w", err)
        }
    } else {
        gasLimit = *ttp.GasLimit
    }
    
    if ttp.Nonce == nil {
        nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
        if err != nil {
            return types.TransferData{}, fmt.Errorf("error getiing pending nonce: %w", err)
        }
    } else {
        nonce = *ttp.Nonce
    }


    tx:= ethTypes.NewTransaction(nonce, tokenAddress, amount, gasLimit, gasPrice, data)
    chainID,err:= client.ChainID(context.Background())
    if err != nil {
        return types.TransferData{}, fmt.Errorf("error creating new transaction: %w", err)
    }

    signedTx, err:= ethTypes.SignTx(tx, ethTypes.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("error signing transaction: %w", err)
    }

    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        return types.TransferData{}, fmt.Errorf(" error sending transaction: %w", err)
    }
    
    reciept, err:= bind.WaitMined(context.Background(), client, signedTx)
    if err != nil {
        return types.TransferData{}, fmt.Errorf("error mining transaction: %w", err)
    }

    return types.TransferData{
        Hash: signedTx.Hash().Hex(),
        Data: reciept,
    }, nil
}

// Get Token Info provides the name, symbol, decimals, token supply and token address of a token.
func GetTokenInfo(tip types.TokenInfoParam) (types.TokenInfo, error) {
    client:= client.EthClient(tip.EndpointURL)
    tokenAddress:= common.HexToAddress(tip.TokenAddress)
    abiData, err:= JsonToABI(tip.ABI)    
    if err != nil {
        return types.TokenInfo{}, fmt.Errorf("error converting ABI to JSON: %w", err)
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
        return types.TokenInfo{}, fmt.Errorf("failed to fetch token name:", err)
    } else if len(resultName) > 0 {
        name = resultName[0].(string)
    }

    err = contract.Call(nil, &resultSymbol, "symbol")
    if err != nil {
        return types.TokenInfo{}, fmt.Errorf("failed to fetch token symbol:", err)
    } else if len(resultSymbol) > 0 {
        symbol = resultSymbol[0].(string)
    }

    err = contract.Call(nil, &resultDecimals, "decimals")
    if err != nil {
        return types.TokenInfo{}, fmt.Errorf("failed to fetch token decimals:", err)
    } else if len(resultDecimals) > 0 {
        decimals = resultDecimals[0].(uint8)
    }

    err = contract.Call(nil, &resultTotalSupply, "totalSupply")
    if err != nil {
        return types.TokenInfo{}, fmt.Errorf("failed to fetch total supply:", err)
    } else if len(resultTotalSupply) > 0 {
        totalSupply = resultTotalSupply[0].(*big.Int)
    }

    return types.TokenInfo{
        Name: name,
        Symbol: symbol,
        Decimals: decimals,
        Supply: *totalSupply,
        TokenAddress: tip.TokenAddress,
    }, nil
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


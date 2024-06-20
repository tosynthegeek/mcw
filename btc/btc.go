package btc

import (
	"encoding/hex"
	"fmt"
	"log"
	"mcw/client"
	"mcw/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// WalletFromMnemonic creates a Bitcoin wallet from a mnemonic and passphrase.
func WalletFromMnemonic(mnemonic string, passphrase string) (types.Wallet, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		log.Fatal("Mnemonic is not valid")
	}

	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derivation path: m/84'/0'/0'/0/0 (for SegWit addresses)
	purpose, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 84)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("failed to derive purpose key: %w", err)
	}
	coinType, err := purpose.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("failed to derive coin type key: %w", err)
	}
	account, err := coinType.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("failed to derive account key: %w", err)
	}
	change, err := account.NewChildKey(0)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("failed to derive change key: %w", err)
	}
	child, err := change.NewChildKey(0)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("failed to derive child key: %w", err)
	}

	privateKey := child.Key

	secpPrivKey, _ := btcec.PrivKeyFromBytes( privateKey)
	pubKey := secpPrivKey.PubKey()

	wif, err := btcutil.NewWIF(secpPrivKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("failed to create WIF: %w", err)
	}

	// Generate SegWit (Bech32) address
	witnessProgram, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubKey.SerializeCompressed()), &chaincfg.MainNetParams)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("failed to create Bech32 address: %w", err)
	}
	address:= witnessProgram.EncodeAddress()

	return types.Wallet{
		Mnemonic:   mnemonic,
		PrivateKey: wif.String(),
		PublicKey:  hex.EncodeToString(pubKey.SerializeCompressed()),
		Address:    address,
	}, nil
}

// CreateWallet generates a new wallet.
func CreateWallet(passphrase string) (types.Wallet, error) {
	entropy, err := bip39.NewEntropy(128) // 12 words
	if err != nil {
		log.Fatal(err.Error())
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatal(err.Error())
	}

	return WalletFromMnemonic(mnemonic, passphrase)
}

// GetAddressFromPrivateKey retrieves the Bitcoin address from a WIF private key.
func GetAddressFromPrivateKey(privateKey string) (types.Address, error) {
	wif, err:= btcutil.DecodeWIF(privateKey)
	if err != nil {
		return types.Address{}, fmt.Errorf("error decoding string: %w", err)
	}

	secpPrivKey:= wif.PrivKey
	pubKey := secpPrivKey.PubKey()

	// Generate SegWit (Bech32) address
	witnessProgram, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubKey.SerializeCompressed()), &chaincfg.MainNetParams)
	if err != nil {
		return types.Address{}, fmt.Errorf("failed to create Bech32 address: %w", err)
	}
	address:= witnessProgram.EncodeAddress()

	return types.Address{
		Address:    address,
		PrivateKey: wif.String(),
	}, nil
}

// GetBalance retrieves the Bitcoin balance for a given address.
func GetBalance(btcPBalancePayload types.BTCBalancePayload) (types.BTCBalance, error) {
	address:= btcPBalancePayload.Address
	client, err:= client.BtcClient(btcPBalancePayload.Config, )
	if err != nil {
		return types.BTCBalance{}, fmt.Errorf("error connecting to client: %w", err)
	}
	defer client.Shutdown()
	unspent, err := client.ListUnspent()
	if err != nil {
		return types.BTCBalance{}, fmt.Errorf("error returning all unspent transactions: %w", err)
	}

	var utxo btcutil.Amount
	for _, u := range unspent {
		if u.Address == address {
			utxo += btcutil.Amount(u.Amount * 1e8)
		}
	}

	// Parse the address
    addr, err := btcutil.DecodeAddress(address, getChainParams(btcPBalancePayload.Config.Network))
    if err != nil {
        return types.BTCBalance{}, fmt.Errorf("invalid address: %w", err)
    }

    // Get the balance for the specific address
    balance, err := client.GetReceivedByAddress(addr)
    if err != nil {
        return types.BTCBalance{}, fmt.Errorf("error getting balance: %w", err)
    }

	return types.BTCBalance{
		UTXO: utxo,
		Address: address,
		Balance: balance,
	}, nil
}

func getChainParams(network string) *chaincfg.Params {
    switch network {
    case "testnet":
        return &chaincfg.TestNet3Params
    case "regtest":
        return &chaincfg.RegressionNetParams
    case "signet":
        return &chaincfg.SigNetParams
    default:
        return &chaincfg.MainNetParams
    }
}

// Transfer performs a Bitcoin transfer from one address to another.
func Transfer(client *rpcclient.Client, fromAddress, toAddress, privateKey string, amount btcutil.Amount) (string, error) {
	wif, err := btcutil.DecodeWIF(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode WIF: %w", err)
	}

	fromAddr, err := btcutil.DecodeAddress(fromAddress, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("invalid from address: %w", err)
	}
	toAddr, err := btcutil.DecodeAddress(toAddress, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("invalid to address: %w", err)
	}

	unspent, err := client.ListUnspent()
	if err != nil {
		return "", fmt.Errorf("failed to list unspent transactions: %w", err)
	}

	var inputs []btcutil.Amount
	var utxos []*btcutil.Tx
	var total btcutil.Amount
	for _, u := range unspent {
		if u.Address == fromAddress {
			hash, err := chainhash.NewHashFromStr(u.TxID)
			if err != nil {
				return "", fmt.Errorf("failed to create hash: %w", err)
			}
			op := wire.NewOutPoint(hash, u.Vout)
			txIn := wire.NewTxIn(op, nil, nil)
			tx := btcutil.NewTx(wire.NewMsgTx(wire.TxVersion))
			tx.MsgTx().AddTxIn(txIn)
			inputs = append(inputs, btcutil.Amount(u.Amount*1e8))
			utxos = append(utxos, tx)
			total += btcutil.Amount(u.Amount * 1e8)
			if total >= amount+1000 { // Include fee
				break
			}
		}
	}

	if total < amount+1000 {
		return "", fmt.Errorf("insufficient funds")
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	for _, utxo := range utxos {
		tx.AddTxIn(utxo.MsgTx().TxIn[0])
	}

	pkScript, err := txscript.PayToAddrScript(toAddr)
	if err != nil {
		return "", fmt.Errorf("failed to create pay-to-addr script: %w", err)
	}
	txOut := wire.NewTxOut(int64(amount), pkScript)
	tx.AddTxOut(txOut)

	change := total - amount - 1000 // Subtract fee
	changeScript, err := txscript.PayToAddrScript(fromAddr)
	if err != nil {
		return "", fmt.Errorf("failed to create change script: %w", err)
	}
	tx.AddTxOut(wire.NewTxOut(int64(change), changeScript))

	for i, txIn := range tx.TxIn {
		sigScript, err := txscript.SignatureScript(tx, i, utxos[i].MsgTx().TxOut[txIn.PreviousOutPoint.Index].PkScript, txscript.SigHashAll, wif.PrivKey, true)
		if err != nil {
			return "", fmt.Errorf("failed to create signature script: %w", err)
		}
		txIn.SignatureScript = sigScript
	}

	// var buf []byte
	err = tx.Serialize(log.Writer())
	if err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %w", err)
	}

	txHash, err := client.SendRawTransaction(tx, true)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}

	return txHash.String(), nil
}

func GetTxByHash(config types.BtcClientConfig, hash string) (*btcjson.GetTransactionResult, error) {
	client, err:= client.BtcClient(config)
	if err != nil {
		return nil, fmt.Errorf("error connecting to client: %w", err)
	}
	defer client.Shutdown()

	chainHash, err:= chainhash.NewHashFromStr(hash)
	if err != nil {
		return nil, fmt.Errorf("error creating hash from string: %w", err)
	}
	tx, err:= client.GetTransaction(chainHash)
	if err != nil {
		return nil, fmt.Errorf("error getting transaction: %w", err)
	}
	
	return tx, nil
}
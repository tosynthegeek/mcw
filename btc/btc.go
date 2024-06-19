package btc

import (
	"fmt"
	"log"
	"mcw/types"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// WalletFromMnemonic creates a Bitcoin wallet from a mnemonic and passphrase.
func WalletFromMnemonic(mnemonic string, passphrase string) types.Wallet {
	if !bip39.IsMnemonicValid(mnemonic) {
		log.Fatal("Mnemonic is not valid")
	}

	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Derivation path: m/44'/0'/0'/0/0
	purpose, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
	if err != nil {
		log.Fatal(err.Error())
	}
	coinType, err := purpose.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		log.Fatal(err.Error())
	}
	account, err := coinType.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		log.Fatal(err.Error())
	}
	change, err := account.NewChildKey(0)
	if err != nil {
		log.Fatal(err.Error())
	}
	child, err := change.NewChildKey(0)
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKey, publicKey := child.Key, child.PublicKey()

	secpPrivKey:= secp256k1.PrivKeyFromBytes(privateKey)

	wif, err := btcutil.NewWIF(secpPrivKey, &chaincfg.MainNetParams, true)
	if err != nil {
		log.Fatal(err.Error())
	}

	address, err := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		log.Fatal(err.Error())
	}

	return types.Wallet{
		Mnemonic:   mnemonic,
		PrivateKey: wif.String(),
		PublicKey:  publicKey.String(),
		Address:    address.EncodeAddress(),
	}
}

// CreateWallet generates a new wallet.
func CreateWallet(passphrase string) types.Wallet {
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
func GetAddressFromPrivateKey(privateKey string) types.Address {
	wif, err := btcutil.DecodeWIF(privateKey)
	if err != nil {
		log.Fatalf("Error decoding WIF: %v", err)
	}

	address, err := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		log.Fatalf("Error creating address: %v", err)
	}

	return types.Address{
		Address:    address.EncodeAddress(),
		PrivateKey: privateKey,
	}
}

// GetBalance retrieves the Bitcoin balance for a given address.
func GetBalance(client *rpcclient.Client, address string) (btcutil.Amount, error) {
	unspent, err := client.ListUnspent()
	if err != nil {
		return 0, err
	}

	var balance btcutil.Amount
	for _, u := range unspent {
		if u.Address == address {
			balance += btcutil.Amount(u.Amount * 1e8)
		}
	}

	return balance, nil
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
package btc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/tosynthegeek/mcw/client"
	"github.com/tosynthegeek/mcw/types"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

type Bitcoin struct {
	cfg types.BtcClientConfig
}

var ErrUnsupportedOperation = errors.New("operation not supported for this blockchain")
// WalletFromMnemonic creates a Bitcoin wallet from a mnemonic and passphrase..
func (b Bitcoin) WalletFromMnemonic(wp types.WalletParam) (types.Wallet, error) {
	if !bip39.IsMnemonicValid(wp.Mnemonic) {
		log.Fatal("Mnemonic is not valid")
	}

	seed := bip39.NewSeed(wp.Mnemonic, wp.Passphrase)
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
		Mnemonic:   wp.Mnemonic,
		PrivateKey: wif.String(),
		PublicKey:  hex.EncodeToString(pubKey.SerializeCompressed()),
		Address:    address,
	}, nil
}

// CreateWallet generates a new wallet.
func (b Bitcoin) CreateWallet(cwp types.CWParam) (types.Wallet, error) {
	entropy, err := bip39.NewEntropy(128) // 12 words
	if err != nil {
		return types.Wallet{}, fmt.Errorf("error generating entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return types.Wallet{}, fmt.Errorf("error creating mnemonic: %w", err)
	}

	wp:= types.WalletParam {
		Mnemonic: mnemonic,
		Passphrase: cwp.Passphrase,
	}

	return b.WalletFromMnemonic(wp)
}

// GetAddressFromPrivateKey retrieves the Bitcoin address from a WIF private key.
func (b Bitcoin) GetAddressFromPrivateKey(privateKey string) (types.Address, error) {
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
func (b Bitcoin) GetBalance(bp types.BalanceParam) (types.Balance, error) {
	address:= bp.Address
	client, err:= client.BtcClient(bp.BtcConfig)
	if err != nil {
		return types.Balance{}, fmt.Errorf("error connecting to client: %w", err)
	}
	defer client.Shutdown()
	unspent, err := client.ListUnspent()
	if err != nil {
		return types.Balance{}, fmt.Errorf("error returning all unspent transactions: %w", err)
	}

	// Get unspent transaction outputs
	var utxo btcutil.Amount
	for _, u := range unspent {
		if u.Address == address {
			utxo += btcutil.Amount(u.Amount * 1e8)
		}
	}

	// Parse the address
    addr, err := btcutil.DecodeAddress(address, bp.BtcConfig.ChainParams)
    if err != nil {
        return types.Balance{}, fmt.Errorf("invalid address: %w", err)
    }

    // Get the balance for the specific address
    balance, err := client.GetReceivedByAddress(addr)
    if err != nil {
        return types.Balance{}, fmt.Errorf("error getting balance: %w", err)
    }

	return types.Balance{
		Data: utxo,
		Address: address,
		Balance: string(balance),
	}, nil
}

func (b Bitcoin) GetTxByHash(hp types.HashParam) (types.TransactionByHash, error) {
	client, err:= client.BtcClient(hp.BtcConfig)
	if err != nil {
		return types.TransactionByHash{}, fmt.Errorf("error connecting to client: %w", err)
	}
	defer client.Shutdown()

	chainHash, err:= chainhash.NewHashFromStr(hp.Hash)
	if err != nil {
		return types.TransactionByHash{}, fmt.Errorf("error creating hash from string: %w", err)
	}
	tx, err:= client.GetTransaction(chainHash)
	if err != nil {
		return types.TransactionByHash{}, fmt.Errorf("error getting transaction: %w", err)
	}
	
	return types.TransactionByHash{
		Transaction: tx,
	}, nil
}

// Transfer performs a Bitcoin transfer from one address to another.
func (b Bitcoin) Transfer(tp types.TransferParam) (types.TransferData, error) {
	client, err:= client.BtcClient(tp.BtcConfig)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("error connecting to client: %w", err)
	}
	defer client.Shutdown()
	wif, err := btcutil.DecodeWIF(tp.PrivateKey)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to decode WIF: %w", err)
	}
	amount:= btcutil.Amount(tp.Amount)
	fromAddr, err := btcutil.DecodeAddress(tp.Sender, &chaincfg.MainNetParams)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("invalid from address: %w", err)
	}
	toAddr, err := btcutil.DecodeAddress(tp.Recipient, &chaincfg.MainNetParams)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("invalid to address: %w", err)
	}

	unspent, err := client.ListUnspent()
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to list unspent transactions: %w", err)
	}

	var inputs []btcutil.Amount
	var utxos []*btcutil.Tx
	var total btcutil.Amount
	for _, u := range unspent {
		if u.Address == tp.Sender {
			hash, err := chainhash.NewHashFromStr(u.TxID)
			if err != nil {
				return types.TransferData{}, fmt.Errorf("failed to create hash: %w", err)
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
		return types.TransferData{}, fmt.Errorf("insufficient funds")
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	for _, utxo := range utxos {
		tx.AddTxIn(utxo.MsgTx().TxIn[0])
	}

	pkScript, err := txscript.PayToAddrScript(toAddr)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to create pay-to-addr script: %w", err)
	}
	txOut := wire.NewTxOut(int64(amount), pkScript)
	tx.AddTxOut(txOut)

	change := total - amount - 1000 // Subtract fee
	changeScript, err := txscript.PayToAddrScript(fromAddr)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to create change script: %w", err)
	}
	tx.AddTxOut(wire.NewTxOut(int64(change), changeScript))

	for i, txIn := range tx.TxIn {
		sigScript, err := txscript.SignatureScript(tx, i, utxos[i].MsgTx().TxOut[txIn.PreviousOutPoint.Index].PkScript, txscript.SigHashAll, wif.PrivKey, true)
		if err != nil {
			return types.TransferData{}, fmt.Errorf("failed to create signature script: %w", err)
		}
		txIn.SignatureScript = sigScript
	}

	// var buf []byte
	err = tx.Serialize(log.Writer())
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	txHash, err := client.SendRawTransaction(tx, true)
	if err != nil {
		return types.TransferData{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	return types.TransferData{
		 Hash: txHash.String(),
		 Data: tx,
	}, nil
}

// Yet to be fully implemented
func (b Bitcoin) GetTokenBalance(tbp types.TBParam) (types.TokenBalance, error) {
	return types.TokenBalance{}, ErrUnsupportedOperation
}

func (b Bitcoin) TransferToken(ttp types.TransferTokenParam) (types.TransferData, error) {
	return types.TransferData{}, ErrUnsupportedOperation
}
func (b Bitcoin) GetTokenInfo(tip types.TokenInfoParam) (types.TokenInfo, error) {
	return types.TokenInfo{}, ErrUnsupportedOperation
}

func (b Bitcoin) SmartContractCall(payload types.SmartContractCallPayload) ([]interface{}, error) {
	return nil, ErrUnsupportedOperation
}
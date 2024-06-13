package main

import (
	"fmt"
	"log"
	"math/big"
	"mcw/eth"
	types "mcw/types"
	"os"
)
func main() {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "mysecretpassword"
	privateKey:= ""
	abiByte, err:= os.ReadFile("./abi/golem.json")
	if err != nil {
		log.Fatal(err.Error())
	}
	network:= "Ethereum"
	abi:= string(abiByte)
	fmt.Println("Abi: ", abi)

	eth.WalletFromMnemonic(mnemonic, passphrase)

	fmt.Println("	")
	eth.CreateWallet(passphrase)

	fmt.Println("Address from Private Key...")
	eth.GetAddressFromPrivKateKey(privateKey)
	eth.JsonToABI(abiByte)
	bp:= types.BalancePayload{
		Address: "0x0536806df512d6cdde913cf95c9886f65b1d3462",
		RpcUrl: "https://cloudflare-eth.com",
		Network: &network,
		TokenAddress: "0xa74476443119A942dE498590Fe1f2454d7D4aC0d",
		ABI: abiByte,
	}
	balance:= eth.GetTokenBalance(bp)
	fmt.Println("Address: ", balance.Address)
	fmt.Println("Balance: ", balance.Balance.String())
	fmt.Printf("Token Address: %s\n", *balance.TokenAddress)

	txHash:= "0x5d49fcaa394c97ec8a9c3e7bd9e8388d420fb050a52083ca52ff24b3b65bc9c2"
	eth.GetTxByHash(txHash, bp.RpcUrl)

	tp:= types.TransferETHPayload {
		PrivateKey: " ",
		RpcUrl: "",
		Recipient: "0xDA01D79Ca36b493C7906F3C032D2365Fb3470aEC",
		Amount: *big.NewInt(10000000),
		Network: &network,
	}

	hash:= "0xbbfe64b5619fcee225294c18575b49e41b647be7737dbfab47261b70a80de8ca"
	// fmt.Println("Initiating Tx....")
	
	// eth.TransferETH(tp)

	eth.GetTxByHash(hash, tp.RpcUrl)
}

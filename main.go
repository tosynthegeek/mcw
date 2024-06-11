package main

import (
	"log"
	"mcw/eth"
	"mcw/types"
	"os"
)
func main() {
	// mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// passphrase := "mysecretpassword"
	// privateKey:= "b5b8eda0c8b55a7f9eafd1f15757c65bebe9ecfb929f41a1bef91055c0a6aa9a"
	abiByte, err:= os.ReadFile("./abi/golem.json")
	if err != nil {
		log.Fatal(err.Error())
	}
	// abi:= string(abiByte)
	// fmt.Println("Abi: ", abi)

	// eth.WalletFromMnemonic(mnemonic, passphrase)

	// fmt.Println("	")
	// eth.CreateWallet(passphrase)

	// fmt.Println("Address from Private Key...")
	// eth.GetAddressFromPrivKateKey(privateKey)
	eth.JsonToABI(abiByte)
	bp:= types.BalancePayload{
		Address: "0x0536806df512d6cdde913cf95c9886f65b1d3462",
		RpcUrl: "https://cloudflare-eth.com",
		Network: "Eth",
		TokenAddress: "0xa74476443119A942dE498590Fe1f2454d7D4aC0d",
		ABI: abiByte,
	}
	eth.GetTokenBalance(bp)
}
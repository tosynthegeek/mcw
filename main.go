package main

import (
	"fmt"
	"mcw/eth"
)
func main() {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "mysecretpassword"
	privateKey:= "b5b8eda0c8b55a7f9eafd1f15757c65bebe9ecfb929f41a1bef91055c0a6aa9a"

	eth.WalletFromMnemonic(mnemonic, passphrase)

	fmt.Println("	")
	eth.CreateWallet(passphrase)

	fmt.Println("Address from Private Key...")
	eth.GetAddressFromPrivKateKey(privateKey)
}
package main

import (
	"mcw/eth"
)
func main() {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "mysecretpassword"

	eth.WalletFromMnemonic(mnemonic, passphrase)
}
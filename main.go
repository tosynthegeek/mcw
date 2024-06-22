package main

import "mcw/aptos"

func main() {
	// mainnet := rpc.MainnetRPCEndpoint
	// devnet := rpc.DevnetRPCEndpoint
	// solAddress := "GLHCm5rMasb1kX7M7QL6Q9SVRWPscXsXpw32bmYgT7xo"
	// UsdcTokenAddress := "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	// txhash := "5CiSEgPuf7WWJHr3CG3uK2qqQdGQ89AZyohHptDy1dfjEEAXmW1ebN2ANPxjKqEggZZK4g15RsWkaUwjsYJouX7U"
	// ctx := context.TODO()
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "mysecretpassword"
	// privateKey := "vymDCylbqtCDlCCyjTe5dU0lmW63XHyl+gf/EpaA63IuC1MJxiBpylRZnMpC/m1ibRxE95HK3lHIpo6cI8wuhA=="
	// abiByte, err := os.ReadFile("./abi/golem.json")
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }
	// network := "Ethereum"
	// abi := string(abiByte)
	// fmt.Println("Abi: ", abi)

	// eth.WalletFromMnemonic(mnemonic, passphrase)

	// fmt.Println("	")
	// eth.CreateWallet(passphrase)

	// fmt.Println("Address from Private Key...")
	// eth.GetAddressFromPrivKateKey(privateKey)
	// eth.JsonToABI(abiByte)
	// bp := types.BalancePayload{
	// 	Address:      "0x0536806df512d6cdde913cf95c9886f65b1d3462",
	// 	RpcUrl:       "https://cloudflare-eth.com",
	// 	Network:      &network,
	// 	TokenAddress: "0xa74476443119A942dE498590Fe1f2454d7D4aC0d",
	// 	ABI:          abiByte,
	// }
	// balance := eth.GetTokenBalance(bp)
	// fmt.Println("Address: ", balance.Address)
	// fmt.Println("Balance: ", balance.Balance.String())
	// fmt.Printf("Token Address: %s\n", *balance.TokenAddress)

	// txHash := "0x5d49fcaa394c97ec8a9c3e7bd9e8388d420fb050a52083ca52ff24b3b65bc9c2"
	// eth.GetTxByHash(txHash, bp.RpcUrl)

	// tp := types.TransferETHPayload{
	// 	PrivateKey: " ",
	// 	RpcUrl:     "",
	// 	Recipient:  "0xDA01D79Ca36b493C7906F3C032D2365Fb3470aEC",
	// 	Amount:     *big.NewInt(10000000),
	// 	Network:    &network,
	// }

	// hash := "0xbbfe64b5619fcee225294c18575b49e41b647be7737dbfab47261b70a80de8ca"
	// fmt.Println("Initiating Tx....")

	// eth.TransferETH(tp)

	// eth.GetTxByHash(hash, tp.RpcUrl)

	// tip := types.TokenInfoPayload{
	// 	RpcUrl:       "https://cloudflare-eth.com",
	// 	TokenAddress: "0xa74476443119A942dE498590Fe1f2454d7D4aC0d",
	// 	ABI:          abiByte,
	// }

	// eth.GetTokenInfo(tip)

	// wallet := sol.GetAddressFromPrivateKey(privateKey)
	// fmt.Println("Wallet PrivateKey: ", wallet.PrivateKey) // 46jmdM8JBsweANkCJZSgQzdUUmwH2TEBcjQQkwhWBjFH
	// fmt.Println("Wallet Address: ", wallet.Address)       // 46jmdM8JBsweANkCJZSgQzdUUmwH2TEBcjQQkwhWBjFH
	// UsdcBalance, err := sol.GetTokenBalance(mainnet, ctx, solAddress, UsdcTokenAddress)
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }
	// fmt.Println(UsdcBalance)
	// mcwAddress := "5oxMcA1ffNmnZWYiqDxPDCxCmpgcNjAxo5tpnuZmCo3M"
	// myAddress := "46jmdM8JBsweANkCJZSgQzdUUmwH2TEBcjQQkwhWBjFH"

	// tx := sol.GetTxByHash(mainnet, ctx, txhash)
	// fmt.Println(tx)

	// client := solClient.NewClient(devnet)
	// str, err := client.RequestAirdrop(context.Background(), myAddress, 20)
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }
	// fmt.Println(str)

	// tsp := types.TransferSolPayload{
	// 	PrivateKey: privateKey,
	// 	RpcUrl:     devnet,
	// 	Recipient:  mcwAddress,
	// 	Amount:     uint64(1000000000),
	// }

	// response, err := sol.TransferSol(tsp)
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }
	// fmt.Println(response)

	// usdc, err := sol.GetTokenInfo(mainnet, ctx, UsdcTokenAddress)
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }
	// fmt.Println(usdc)
	// addr := common.PublicKeyFromString(UsdcTokenAddress)
	// meta, err := sol.GetTokenMetadata(mainnet, ctx, addr)
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }

	// fmt.Println(meta)

	// btcwallet, err := btc.WalletFromMnemonic(mnemonic, passphrase)
	// if err != nil {

	// 	log.Fatal(err.Error())
	// }
	// fmt.Println(btcwallet) // bc1qdhwtj0j9pxfckduaey0w5d5mhvuv4f7y059s5v
	// btcPrivKey := "KxiNrPvQ33PNtMuAywpE2mbZNLR3CzWQaKZGeuzKfQhFwZ2E92vb"
	// // btcAddress := "bc1qqv48lhfhqjz8au3grvnc6nxjcmhzsuucj80frr"
	// btcWallet, err := btc.CreateWallet(passphrase)
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }
	// fmt.Println(btcWallet)
	// address, err := btc.GetAddressFromPrivateKey(btcPrivKey)
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }
	// fmt.Println(address)
	aptos.WalletFromMnemonic(mnemonic, passphrase)
}

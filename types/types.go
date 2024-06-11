package types

// Wallet contains the mnemonic, private key, public key and address.
type Wallet struct {
	Mnemonic   string
	PrivateKey string
	PublicKey  string
	Address    string
}

type Address struct {
	Address    string
	PrivateKey string
}
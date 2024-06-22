package client

import (
	"fmt"
	"mcw/types"
	"os"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/ethereum/go-ethereum/ethclient"
)

func EthClient(rpcUrl string) *ethclient.Client {
	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		fmt.Println("Error connecting to client: ", err)
	}

	return client
}

func BtcClient(cfg types.BtcClientConfig) (*rpcclient.Client, error) {
	connCfg := &rpcclient.ConnConfig{
		Host:                 cfg.Host,
		User:                 cfg.User,
		Pass:                 cfg.Pass,
		HTTPPostMode:         true,
		DisableTLS:           !cfg.UseTLS,
		Proxy:                cfg.Proxy,
		ProxyUser:            cfg.ProxyUser,
		ProxyPass:            cfg.ProxyPass,
		ExtraHeaders:         cfg.ExtraHeaders,
		DisableAutoReconnect: true, // Depending on your use case
	}

	if cfg.UseTLS && cfg.CertPath != "" {
		certs, err := os.ReadFile(cfg.CertPath)
		if err != nil {
			return nil, fmt.Errorf("could not read certificate file: %v", err)
		}
		connCfg.Certificates = certs
	}

	switch cfg.Network {
	case "mainnet":
		connCfg.Params = chaincfg.MainNetParams.Name
	case "testnet":
		connCfg.Params = chaincfg.TestNet3Params.Name
	case "regtest":
		connCfg.Params = chaincfg.RegressionNetParams.Name
	case "signet":
		connCfg.Params = chaincfg.SigNetParams.Name
	default:
		connCfg.Params = chaincfg.MainNetParams.Name // Default to mainnet
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %v", err)
	}

	return client, nil
}

func AptosClient(network string) (*aptos.Client, error) {
	
	var config aptos.NetworkConfig
	switch network {
	case "mainnet":
		config = aptos.MainnetConfig
	case "devnet":
		config = aptos.DevnetConfig
	case "local":
		config = aptos.LocalnetConfig
	default:
		config = aptos.MainnetConfig
	}

	client, err:= aptos.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aptos client: %w", err)
	}

	return client, err
}
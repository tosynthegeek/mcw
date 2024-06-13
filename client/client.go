package client

import (
	"fmt"

	solClient "github.com/blocto/solana-go-sdk/client"
	solRpc "github.com/blocto/solana-go-sdk/rpc"
	"github.com/ethereum/go-ethereum/ethclient"
)

func EthClient(rpcUrl string) *ethclient.Client {
	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		fmt.Println("Error connecting to client: ", err)
	}

	return client
}

func SolClient() (*solClient.Client) {
	client:= solClient.NewClient(solRpc.MainnetRPCEndpoint)

	return client
}
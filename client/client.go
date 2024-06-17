package client

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
)

func EthClient(rpcUrl string) *ethclient.Client {
	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		fmt.Println("Error connecting to client: ", err)
	}

	return client
}
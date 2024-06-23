package internal

import (
	"bytes"
	"log"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

//JsonToABI converts imported ABI in JSON into type abi.ABI
func JsonToABI(abiData []byte) (abi.ABI, error) {
    parsedABI, err := abi.JSON(bytes.NewReader(abiData))
	if err != nil {
		log.Fatal("failed to parse ABI: ", err)
	}

    return parsedABI, nil
}
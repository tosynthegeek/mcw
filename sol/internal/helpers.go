package internal

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tosynthegeek/mcw/types"

	solClient "github.com/blocto/solana-go-sdk/client"
	"github.com/blocto/solana-go-sdk/common"
)

func GetTokenMetadata(endpoint string, ctx context.Context, mintAddress common.PublicKey) (types.TokenMetaData, error) {
	client:= solClient.NewClient(endpoint)
    metadataProgram := common.PublicKeyFromString("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s") // Metaplex Token Metadata Program
    metadataAddress, _, err := common.FindProgramAddress(
        [][]byte{
            []byte("metadata"),
            metadataProgram.Bytes(),
            mintAddress.Bytes(),
        },
        metadataProgram,
    )
	if err != nil {
	    return types.TokenMetaData{}, fmt.Errorf("failed to find metadata address: %w", err)
	}

    accountInfo, err := client.GetAccountInfo(ctx, metadataAddress.ToBase58())
    if err != nil {
        return types.TokenMetaData{}, fmt.Errorf("failed to get metadata account info: %w", err)
    }

	fmt.Println(accountInfo.Data)
    // This is a simplified parsing. You'll need to implement proper
    // deserialization based on the Token Metadata Program's data structure
    var metadata types.TokenMetaData

    // This assumes the metadata is stored as JSON. Adjust as necessary.
    err = json.Unmarshal(accountInfo.Data, &metadata)
    if err != nil {
        return types.TokenMetaData{}, fmt.Errorf("failed to parse metadata: %w", err)
    }


	return metadata, nil
}
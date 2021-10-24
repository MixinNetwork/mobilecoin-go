package api

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFogAddress(t *testing.T) {
	assert := assert.New(t)
	hint, err := fakeOnetimeHint()
	assert.Equal(err, nil)
	assert.Equal(EncryptedFogHintSize, len(hint))

	// Added to demonstrate usage. The public address came from decoding a b58 address I grabbed
	// from my Signal Testnet installation.
	fmt.Printf("-------------------------------------------\n")
	/*
		pub_addr, err := DecodeAccount("jHVgJvZ58qHzTCTJDZDW27GSxUuutwUcBd8uMy4TkxYCnKenbc2qrmFBN3p4tC2xsLuCH9WJkaCrGM6KjBzC7UtYhsE5RctLTiHMUvMd83FZRfwpmC6bMjvp4iHa8zHhPpjDKZk34zbid5M2WhwKdR3SUfHsZ1o4fueNJVp3VRWcyPX9R8yhEBty5QHkWKzjEWg6Z1d8XHeaPMHS3w25MTZit7WnMpVo5KGBLxD8NML4horcFGCmM5QnXB6gvGCfhH")
		assert.Nil(err)
	*/

	pub_addr, err := DecodeAccount("p4AiFQacuao8tshGwjd7gzQys239uhnajW65N76TUjgutQSRxsn6HDPbsykPjz83UZhj9a2oYhbTVjecopxh17B6rTEbkcNUv2TcME8XcrLSkMjzB3bPpRsknWWidACuMT5kz4shRkKy1WH4NTbQ7uEbfmvZgg5rVcwhC6HrAiAGhhmcCCrPEaJRQuKc4tLALAQkF4ZGMvCX8R4p5HbmJDyFf3VU1ewu1nWLhZTDCAje4xbBGDMozkfQcoHnKc")

	reportResp, err := GetFogPubkeyRust(pub_addr)
	assert.Equal(err, nil)

	log.Printf("[go] fully validated fog pub key expiry: %d\n", reportResp.pubkey_expiry)
	log.Printf("[go] fully validated fog pub key expiry: %s\n", hex.EncodeToString(reportResp.pubkey_bytes))

	fmt.Printf("-------------------------------------------\n")
}

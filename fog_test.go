package api

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFogAddress_Testnet(t *testing.T) {
	assert := assert.New(t)
	hint, err := fakeOnetimeHint()
	assert.Equal(err, nil)
	assert.Equal(EncryptedFogHintSize, len(hint))

	// Added to demonstrate usage. The public address came from decoding a b58 address I grabbed
	// from my Signal Testnet installation.
	fmt.Printf("-------------------------------------------\n")

	// TESTNET FOG ENABLED, 
  pub_addr, err := DecodeAccount("p4AiFQacuao8tshGwjd7gzQys239uhnajW65N76TUjgutQSRxsn6HDPbsykPjz83UZhj9a2oYhbTVjecopxh17B6rTEbkcNUv2TcME8XcrLSkMjzB3bPpRsknWWidACuMT5kz4shRkKy1WH4NTbQ7uEbfmvZgg5rVcwhC6HrAiAGhhmcCCrPEaJRQuKc4tLALAQkF4ZGMvCX8R4p5HbmJDyFf3VU1ewu1nWLhZTDCAje4xbBGDMozkfQcoHnKc")

	assert.Nil(err)

	reportResp, err := GetFogPubkeyRust(pub_addr)
	assert.Equal(err, nil)

	log.Printf("[go] fully validated fog pub key expiry: %d\n", reportResp.pubkey_expiry)
	log.Printf("[go] fully validated fog pub key expiry: %s\n", hex.EncodeToString(reportResp.pubkey_bytes))

	fmt.Printf("-------------------------------------------\n")
}

func TestFogAddress_Mainnet(t *testing.T) {
	assert := assert.New(t)
	hint, err := fakeOnetimeHint()
	assert.Equal(err, nil)
	assert.Equal(EncryptedFogHintSize, len(hint))

	// Added to demonstrate usage. The public address came from decoding a b58 address I grabbed
	// from my Signal Testnet installation.
	fmt.Printf("-------------------------------------------\n")

	// MAINNET FOG ENABLED
  pub_addr, err := DecodeAccount("NzUGiruc2cJbKhQobxHpJpXYJvQdV8PfhuCZvyZE3B3iFJKMxThK5vkGZP7YuNbxuTcxPH7CwftuQX7YxZKaHpZgzHCR4m53JnvrKf9FoFdSXkJmHxHYyv6AdeNzy4PbRgy7yrwfrQfwdqTMYXWR2PYgkLuAVL4YQLCx7xiCQfvLv8uryjg8joBVYdsUKr2ZZEMAu2AZPv2Wnz4AxHaSJ9xRCScUwf7zZm1VZkxVth7GqxbW8gk")

	assert.Nil(err)

	reportResp, err := GetFogPubkeyRust(pub_addr)
	assert.Equal(err, nil)

	log.Printf("[go] fully validated fog pub key expiry: %d\n", reportResp.pubkey_expiry)
	log.Printf("[go] fully validated fog pub key expiry: %s\n", hex.EncodeToString(reportResp.pubkey_bytes))

	fmt.Printf("-------------------------------------------\n")
}

package api

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFog(t *testing.T) {
	assert := assert.New(t)
	hint, err := fakeOnetimeHint()
	assert.Equal(err, nil)
	assert.Equal(EncryptedFogHintSize, len(hint))

	// Added to demonstrate usage. The public address came from decoding a b58 address I grabbed
	// from my Signal Testnet installation.
	fmt.Printf("-------------------------------------------\n")
	pub_addr, err := DecodeAccount("test-account")
	assert.Nil(err)

	reportResp, err := GetFogPubkeyRust(pub_addr)
	assert.Equal(err, nil)

	fmt.Printf("[go] fully validated fog pub key expiry: %d\n", reportResp.pubkey_expiry)
	fmt.Printf("[go] fully validated fog pub key expiry: %s\n", hex.EncodeToString(reportResp.pubkey_bytes))

	fmt.Printf("-------------------------------------------\n")
}

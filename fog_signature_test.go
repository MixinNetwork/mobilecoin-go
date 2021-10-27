package api

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSignature(t *testing.T) {
	assert := assert.New(t)
	signature, err := ParseSignature()
	assert.Nil(err)

	signer := signature.MrSigner()
	log.Println(hex.EncodeToString(signer[:]))

	enclave := signature.MRENCLAVE()
	log.Println(hex.EncodeToString(enclave[:]))
}

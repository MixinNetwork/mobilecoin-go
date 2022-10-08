package api

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGog(t *testing.T) {
	assert := assert.New(t)

	signature, err := ParseSignature()
	assert.Nil(err)

	enclave := signature.MRENCLAVE()
	log.Println(hex.EncodeToString(enclave[:]))
}

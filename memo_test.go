package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
)

func TestMemo(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 66)
	_, err := rand.Read(data)
	assert.Nil(err)

	var public ristretto.Point
	public.Rand()
	var private ristretto.Scalar
	private.Rand()
	memo, err := EncryptMemo(hex.EncodeToString(data), &public, &private)
	assert.Nil(err)
	assert.Len(memo, 66)
	plain, err := DecryptMemo(hex.EncodeToString(memo), &public, &private)
	assert.Nil(err)
	assert.True(bytes.Compare(data, plain) == 0)
}

package api

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
)

// https://github.com/mobilecoinfoundation/mobilecoin/blob/2f90154a445c769594dfad881463a2d4a003d7d6/fog/sig/authority/src/ristretto.rs#L33
func TestFogResolver(t *testing.T) {
	assert := assert.New(t)

	TEST_MSG := `The era of "electronic mail" may soon be upon us;`
	log.Println(hex.EncodeToString([]byte(TEST_MSG)))
	privateStr := "ff17ce59b27d3b3d0280f3df7037c2715128043daba5df47e7735ed2ccef2c01"
	sig := "821e1c768da2db0477dd6fd6cf4ab400bcd0678bbaf8463926d43ced79bcc41474e623658ec388c87d43cfd54155e929fc4611eede0f92f6554d263107d96f8c"

	privateBuf, err := hex.DecodeString(privateStr)
	assert.Nil(err)
	var privateBuf32 [32]byte
	copy(privateBuf32[:], privateBuf)
	var private ristretto.Scalar
	private.SetBytes(&privateBuf32)
	var point ristretto.Point
	point.PublicScalarMultBase(&private)
	log.Println("RistrettoPublic:::", hex.EncodeToString(point.Bytes()))

	signingCtx := []byte(SUPER_CONTEXT)
	verifyTranscript := schnorrkel.NewSigningContext(signingCtx, []byte(TEST_MSG))

	sigbuf, err := hex.DecodeString(sig)
	assert.Nil(err)
	var sig64 [64]byte
	copy(sig64[:], sigbuf)
	signature := schnorrkel.Signature{}
	err = signature.Decode(sig64)
	assert.Nil(err)

	var view32 [32]byte
	copy(view32[:], point.Bytes())
	public := schnorrkel.NewPublicKey(view32)
	assert.True(public.Verify(&signature, verifyTranscript))
}

package api

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
)

func testTranscript(t *testing.T) {
	assert := assert.New(t)

	tt := InitialTranscript(BULLETPROOF_DOMAIN_TAG)
	RangeproofDomainSep(64, 64, tt)
	assert.Equal("fdb12c0aa082b37704c2188b44c6ebe27c35263d49f86abb56221b7376408930", hex.EncodeToString(tt.ExtractBytes([]byte("digest32"), 32)))

	tt = InitialTranscript(BULLETPROOF_DOMAIN_TAG)
	assert.Equal("b8ad943d1e31c5c4a95a957ac92e2f058818f64773503c51357268b25af27422", hex.EncodeToString(tt.ExtractBytes([]byte("digest32"), 32)))
	RangeproofDomainSep(64, 64, tt)
	assert.Equal("1863740161d2ec5b8847136c8ff413aced585a3fc58d5f8d3645e664c784954e", hex.EncodeToString(tt.ExtractBytes([]byte("digest32"), 32)))

	tt = InitialTranscript(BULLETPROOF_DOMAIN_TAG)
	tt = RangeproofDomainSep(64, 64, tt)
	assert.Equal("fdb12c0aa082b37704c2188b44c6ebe27c35263d49f86abb56221b7376408930", hex.EncodeToString(tt.ExtractBytes([]byte("digest32"), 32)))

	tt = InitialTranscript(BULLETPROOF_DOMAIN_TAG)
	ttclone1 := *tt
	ttclone2 := *tt
	RangeproofDomainSep(64, 64, &ttclone2)
	log.Println(hex.EncodeToString(ttclone1.ExtractBytes([]byte("digest32"), 32)))
	log.Println(hex.EncodeToString(ttclone2.ExtractBytes([]byte("digest32"), 32)))

	tt = InitialTranscript("AggregatedRangeProofTest")
	assert.Equal("db5b088dc7cad6e71ae2d58ec24fc638b5f1b3a2d5eb005724fb1487a975baa00c10496c7fd1909d22bbdbc1a7e28e6b41ac4590651ec90f7ef4e8e694a5fb88", hex.EncodeToString(tt.ExtractBytes([]byte("y"), 64)))

	tt = InitialTranscript("AggregatedRangeProofTest")
	RangeproofDomainSep(32, 4, tt)
	data := tt.ExtractBytes([]byte("y"), 64)
	assert.Equal("8c9e7d8be647b6a1075e89116015d2610bb2af0e9ec21155aac3371284f6688aace5630ea6f01e885d39b9a2bf91f412dc777c672b30895c480b99b3404c8f10", hex.EncodeToString(data))
	assert.Equal("2f35e7225a239904853604bf8368dc14a5181ab697eb9880fe850b02a2e12e06", hex.EncodeToString(fromBytesModOrderWide(data).Bytes()))

	var r, r1, r2 ristretto.Point
	r1.Rand()
	r2.Rand()
	assert.Equal(hex.EncodeToString(r.Add(&r1, &r2).Bytes()), hex.EncodeToString(r1.Add(&r1, &r2).Bytes()))
	assert.Equal(hex.EncodeToString(r.Add(&r1, &r2).Bytes()), hex.EncodeToString(r1.Add(&r1, &r2).Bytes()))
}

package api

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
)

func testGenerateRangeProofs(t *testing.T) {
	assert := assert.New(t)

	values := []uint64{1, 3, 4, 5}
	bblindings := make([]*ristretto.Scalar, 4)
	for i, v := range values {
		bblindings[i] = uint64ToScalar(uint64(v))
	}
	for i, b := range bblindings {
		log.Println("bblindings", i, hex.EncodeToString(b.Bytes()))
	}

	bpGens := NewBulletproofGens(64, 64)
	pcGens := DefaultPedersenGens()
	proof, commitments, err := GenerateRangeProofs(bpGens, pcGens, values, bblindings)
	assert.Nil(err)
	assert.NotNil(proof)
	assert.Len(commitments, 4)
	for i, c := range commitments {
		log.Println("commitments", i, hex.EncodeToString(c.Bytes()))
	}

	log.Println("proof A", hex.EncodeToString(proof.A.Bytes()))
	log.Println("proof S", hex.EncodeToString(proof.S.Bytes()))
	log.Println("proof T1", hex.EncodeToString(proof.T1.Bytes()))
	log.Println("proof T2", hex.EncodeToString(proof.T2.Bytes()))
	log.Println("proof TX", hex.EncodeToString(proof.TX.Bytes()))
	log.Println("proof TXBlinding", hex.EncodeToString(proof.TXBlinding.Bytes()))
	log.Println("proof EBlinding", hex.EncodeToString(proof.EBlinding.Bytes()))
	for i, l := range proof.IPPProof.LVec {
		log.Println("proof InnerProductProof LVec", i, hex.EncodeToString(l.Bytes()))
	}
	for i, r := range proof.IPPProof.RVec {
		log.Println("proof InnerProductProof RVec", i, hex.EncodeToString(r.Bytes()))
	}
	log.Println("proof InnerProductProof A", hex.EncodeToString(proof.IPPProof.A.Bytes()))
	log.Println("proof InnerProductProof B", hex.EncodeToString(proof.IPPProof.B.Bytes()))

	log.Println("proof:::", hex.EncodeToString(proof.ToBytes()))
}

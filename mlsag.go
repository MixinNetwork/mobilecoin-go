package api

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bwesterb/go-ristretto"
	"github.com/dchest/blake2b"
)

func signRing(message []byte, inputs []*TxOut, realIndex int, onetimePrivateKey *ristretto.Scalar, value uint64, blinding, outputBlinding *ristretto.Scalar) (*RingMLSAG, error) {
	size := len(inputs)
	if realIndex >= size {
		return nil, fmt.Errorf("Invalid inputs size %d and realIndex: %d", len(inputs), realIndex)
	}

	// generators := NewPedersenGens()  // useless
	// G = GENERATORS.B_blinding // B_blinding is Base Point

	// key image, I = KeyImage
	keyImage := keyImageFromPrivate(onetimePrivateKey)
	I := keyImage

	outputCommitment := NewCommitment(value, outputBlinding)

	// decompress_ring CompressedRistrettoPublic = tx_out.target_key, CompressedCommitment = tx_out.amount.commitment

	c := make([]*ristretto.Scalar, size)
	for i := range c {
		var zero ristretto.Scalar
		c[i] = zero.SetZero()
	}

	r := make([]*ristretto.Scalar, 2*size)
	for i := 0; i < size; i++ {
		if i == realIndex {
			continue
		}
		var r1, r2 ristretto.Scalar
		r[2*i] = r1.Rand()
		r[2*i+1] = r2.Rand()
	}

	var alpha0, alpha1 ristretto.Scalar
	alpha0.Rand()
	alpha1.Rand()

	for n := 0; n < size; n++ {
		i := (realIndex + n) % size
		// P is TargetKey
		p_i := hexToPoint(inputs[i].TargetKey)
		inputCommitment := hexToPoint(inputs[i].Amount.Commitment)

		var L0, L1, R0 ristretto.Point
		if i == realIndex {
			L0.ScalarMultBase(&alpha0)
			R0.ScalarMult(hashToPoint(p_i), &alpha0)
			L1.ScalarMultBase(&alpha1)
		} else {
			var L00, L01 ristretto.Point
			L0.Add(L00.ScalarMultBase(r[2*i]), L01.ScalarMult(p_i, c[i]))
			var R00, R01 ristretto.Point
			R0.Add(R00.ScalarMult(hashToPoint(p_i), r[2*i]), R01.ScalarMult(I, c[i]))
			var L10, L11, L12 ristretto.Point
			L1.Add(L10.ScalarMultBase(r[2*i+1]), L11.ScalarMult(L12.Sub(outputCommitment, inputCommitment), c[i]))
		}

		c[(i+1)%size] = challenge(message, keyImage, &L0, &R0, &L1)
	}

	var s0, s1 ristretto.Scalar
	r[2*realIndex] = s0.Sub(&alpha0, s1.Mul(c[realIndex], onetimePrivateKey))
	var z0, z1, z2 ristretto.Scalar
	r[2*realIndex+1] = z0.Sub(&alpha1, z1.Mul(c[realIndex], z2.Sub(outputBlinding, blinding)))

	if true {
		inputCommitment := hexToPoint(inputs[realIndex].Amount.Commitment)

		var different ristretto.Point
		different.Sub(outputCommitment, inputCommitment)

		var z ristretto.Scalar
		z.Sub(outputBlinding, blinding)
		var r ristretto.Point
		if bytes.Compare(different.Bytes(), r.ScalarMultBase(&z).Bytes()) != 0 {
			return nil, errors.New("Value Not Conserved")
		}
	}

	responses := make([]string, len(r))
	for i, rr := range r {
		responses[i] = hex.EncodeToString(rr.Bytes())
	}
	return &RingMLSAG{
		CZero:     hex.EncodeToString(c[0].Bytes()),
		Responses: responses,
		KeyImage:  hex.EncodeToString(keyImage.Bytes()),
	}, nil
}

func challenge(message []byte, keyImage *ristretto.Point, L0, R0, L1 *ristretto.Point) *ristretto.Scalar {
	hash := blake2b.New512()
	hash.Write([]byte(RING_MLSAG_CHALLENGE_DOMAIN_TAG))
	hash.Write(message)
	hash.Write(keyImage.Bytes())
	hash.Write(L0.Bytes())
	hash.Write(R0.Bytes())
	hash.Write(L1.Bytes())

	var key [64]byte
	copy(key[:], hash.Sum(nil))

	var s ristretto.Scalar
	return s.SetReduced(&key)
}

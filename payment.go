package api

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"io"

	account "github.com/MixinNetwork/mobilecoin-account"
	"github.com/bwesterb/go-ristretto"
	"github.com/dchest/blake2b"
	"golang.org/x/crypto/hkdf"
)

func keyImage(private *ristretto.Scalar) *ristretto.Point {
	var p ristretto.Point
	p.ScalarMultBase(private)

	hash := blake2b.New512()
	hash.Write([]byte(HASH_TO_POINT_DOMAIN_TAG))
	hash.Write([]byte(p.Bytes()))
	var key [64]byte
	copy(key[:], hash.Sum(nil))

	var r1Bytes, r2Bytes [32]byte
	copy(r1Bytes[:], key[:32])
	copy(r2Bytes[:], key[32:])
	var r, r1, r2 ristretto.Point
	return r.Add(r1.SetElligator(&r1Bytes), r2.SetElligator(&r2Bytes))
}

func GetValueWithBlinding(output *TxOut, viewPrivate *ristretto.Scalar) (uint64, *ristretto.Scalar) {
	secret := createSharedSecret(hexToPoint(output.PublicKey), viewPrivate)

	mask := GetValueMask(secret)
	maskedValue := uint64(output.Amount.MaskedValue)
	value := maskedValue ^ mask

	blinding := GetBlinding(secret)
	return value, blinding
}

func GetValueWithBlindingNew(viewPrivate, publicKey string, maskedValue uint64) (uint64, *ristretto.Scalar) {
	secret := account.SharedSecret(viewPrivate, publicKey)
	mask := GetValueMask(secret)
	value := maskedValue ^ mask
	blinding := GetBlinding(secret)
	return value, blinding
}

func GetValueMask(secret *ristretto.Point) uint64 {
	hash := blake2b.New512()
	hash.Write([]byte(AMOUNT_VALUE_DOMAIN_TAG))
	hash.Write(secret.Bytes())

	var hs ristretto.Scalar
	var key [64]byte
	copy(key[:], hash.Sum(nil))
	return binary.LittleEndian.Uint64(hs.SetReduced(&key).Bytes()[:8])
}

func GetBlinding(secret *ristretto.Point) *ristretto.Scalar {
	hash := blake2b.New512()
	hash.Write([]byte(AMOUNT_BLINDING_DOMAIN_TAG))
	hash.Write(secret.Bytes())

	var hs ristretto.Scalar
	var key [64]byte
	copy(key[:], hash.Sum(nil))
	return hs.SetReduced(&key)
}

func NewCommitment(value uint64, blinding *ristretto.Scalar) *ristretto.Point {
	// value scalar
	v := uint64ToScalar(value)

	generators := NewPedersenGens()
	return generators.Commit(v, blinding)
}

func generatorsBlinding(base *ristretto.Point) *ristretto.Point {
	hash := blake2b.New512()
	hash.Write([]byte(HASH_TO_POINT_DOMAIN_TAG))
	hash.Write(base.Bytes())
	var key [64]byte
	copy(key[:], hash.Sum(nil))

	var r1Bytes, r2Bytes [32]byte
	copy(r1Bytes[:], key[:32])
	copy(r2Bytes[:], key[32:])
	var r, r1, r2 ristretto.Point
	return r.Add(r1.SetElligator(&r1Bytes), r2.SetElligator(&r2Bytes))
}

func RecoverPublicSubaddressSpendKey(viewPrivate, onetimePublicKey, publicKey string) (*ristretto.Point, error) {
	var a ristretto.Scalar
	R := hexToPoint(publicKey)
	var aBytes [32]byte
	aData, err := hex.DecodeString(viewPrivate)
	if err != nil {
		return nil, err
	}
	copy(aBytes[:], aData)

	// hs
	var hsp ristretto.Point
	var hs ristretto.Scalar
	hash := blake2b.New512()
	hash.Write([]byte(HASH_TO_SCALAR_DOMAIN_TAG))
	hash.Write(hsp.ScalarMult(R, a.SetBytes(&aBytes)).Bytes())
	var key [64]byte
	copy(key[:], hash.Sum(nil))

	// p
	p := hexToPoint(onetimePublicKey)

	var g ristretto.Point
	var r1, r ristretto.Point
	return r.Sub(p, r1.ScalarMult(g.SetBase(), hs.SetReduced(&key))), nil
}

// get_blinding_factors
func GetBlindingFactorsV2(secret []byte) (uint64, error) {
	hash := sha512.New

	value_mask := make([]byte, 8)
	hkdf3 := hkdf.New(hash, secret, []byte(AMOUNT_BLINDING_FACTORS_DOMAIN_TAG), []byte(AMOUNT_VALUE_DOMAIN_TAG))
	_, err := io.ReadFull(hkdf3, value_mask)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(value_mask), nil
}

// compute_commitment
func ComputeCommitmentV2(masked_value uint64, secret []byte) (uint64, error) {
	value_mask, err := GetBlindingFactorsV2(secret)
	if err != nil {
		return 0, err
	}
	value := masked_value ^ value_mask
	return value, nil
}

// get_value_from_amount_shared_secret
func GetValueFromAmountSharedSecretV2(maskedValue uint64, secret *ristretto.Point) (uint64, error) {
	amount_shared_secret := ComputeAmountSharedSecretV2(secret)
	return ComputeCommitmentV2(maskedValue, amount_shared_secret)
}

// compute_amount_shared_secret
func ComputeAmountSharedSecretV2(secret *ristretto.Point) []byte {
	hash := blake2b.New512()
	hash.Write([]byte(AMOUNT_SHARED_SECRET_DOMAIN_TAG))
	hash.Write(secret.Bytes())

	var key [64]byte
	copy(key[:], hash.Sum(nil))
	return key[:32]
}

func GetValueV2(amount *Amount, viewPrivate, publicKey string) (uint64, error) {
	secret := account.SharedSecret(viewPrivate, publicKey)
	maskedValue := uint64(amount.MaskedValue)
	return GetValueFromAmountSharedSecretV2(maskedValue, secret)
}

func GetValue(output *TxOut, viewPrivate string) (uint64, error) {
	if output.Amount.Version == 2 {
		return GetValueV2(output.Amount, viewPrivate, output.PublicKey)
	}
	value, _ := GetValueWithBlindingNew(viewPrivate, output.PublicKey, uint64(output.Amount.MaskedValue))
	return value, nil
}

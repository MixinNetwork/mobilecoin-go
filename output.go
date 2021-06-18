package api

import (
	"encoding/hex"

	"github.com/bwesterb/go-ristretto"
	"github.com/dchest/blake2b"
)

type OutputWithSharedSecret struct {
	TxOut        *TxOut
	Receiver     *PublicAddress
	Value        uint64
	Blinding     *ristretto.Scalar
	Secret       *ristretto.Point
	Confirmation []byte
	Index        int
}

func CreateOutput(value uint64, recipient *PublicAddress, index int) (*OutputAndSharedSecret, string, error) {
	var r ristretto.Scalar
	r.Rand()

	hint, err := FakeFogHint()
	if err != nil {
		return nil, "", err
	}
	target := createOnetimePublicKey(&r, recipient)
	public := createTxPublicKey(&r, hexToPoint(recipient.SpendPublicKey))

	view := hexToPoint(recipient.ViewPublicKey)
	secret := createSharedSecret(view, &r)
	amount, _ := newAmount(value, secret)

	output := &TxOut{
		Amount:    amount,
		TargetKey: hex.EncodeToString(target.Bytes()),
		PublicKey: hex.EncodeToString(public.Bytes()),
		EFogHint:  hex.EncodeToString(hint),
	}

	return &OutputAndSharedSecret{
		Output:       output,
		SharedSecret: secret,
		Index:        index,
		Receiver:     recipient,
		Value:        value,
	}, hex.EncodeToString(public.Bytes()), nil
}

func newAmount(value uint64, secret *ristretto.Point) (*Amount, *ristretto.Scalar) {
	blinding := GetBlinding(secret)
	commitment := NewCommitment(value, blinding)
	mask := GetValueMask(secret)
	maskedValue := value ^ mask
	return &Amount{
		Commitment:  hex.EncodeToString(commitment.Bytes()),
		MaskedValue: MaskedValue(maskedValue),
	}, blinding
}

func createOnetimePublicKey(private *ristretto.Scalar, recipient *PublicAddress) *ristretto.Point {
	R := hexToPoint(recipient.ViewPublicKey)
	D := hexToPoint(recipient.SpendPublicKey)

	hs := hashToScalar(R, private)
	var r1, r ristretto.Point
	var g ristretto.Point
	return r.Add(r1.ScalarMult(g.SetBase(), hs), D)
}

func createTxPublicKey(private *ristretto.Scalar, spend *ristretto.Point) *ristretto.Point {
	var r ristretto.Point
	return r.ScalarMult(spend, private)
}

func RecoverOnetimePrivateKey(public, private string) (*ristretto.Scalar, error) {
	view := private[:64]
	spend := private[64:]

	account, err := NewAccountKey(view, spend)
	if err != nil {
		return nil, err
	}

	pk := hexToPoint(public)
	// `Hs( a * R )`
	Hs := hashToScalar(pk, account.ViewPrivateKey)
	d := account.SubaddressSpendPrivateKey(0)

	var x ristretto.Scalar
	return x.Add(Hs, d), nil
}

func ConfirmationNumberFromSecret(secret *ristretto.Point) []byte {
	hash := blake2b.New256()
	hash.Write([]byte(TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG))
	hash.Write(secret.Bytes())
	return hash.Sum(nil)
}

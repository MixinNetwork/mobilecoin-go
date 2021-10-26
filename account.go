package api

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"

	"github.com/MixinNetwork/mobilecoin-go/block"
	"github.com/btcsuite/btcutil/base58"
	"github.com/bwesterb/go-ristretto"
	"github.com/dchest/blake2b"
	"google.golang.org/protobuf/proto"
)

type Account struct {
	ViewPrivateKey  *ristretto.Scalar
	SpendPrivateKey *ristretto.Scalar
}

func NewAccountKey(viewPrivate, spendPrivate string) (*Account, error) {
	var viewBytes [32]byte
	viewData, err := hex.DecodeString(viewPrivate)
	if err != nil {
		return nil, err
	}
	copy(viewBytes[:], viewData)

	var view ristretto.Scalar
	account := &Account{
		ViewPrivateKey: view.SetBytes(&viewBytes),
	}
	if spendPrivate != "" {
		var spendBytes [32]byte
		spendData, err := hex.DecodeString(spendPrivate)
		if err != nil {
			return nil, err
		}
		copy(spendBytes[:], spendData)
		var spend ristretto.Scalar
		account.SpendPrivateKey = spend.SetBytes(&spendBytes)
	}
	return account, nil
}

func ViewPrivateKeyFromHex(viewPrivate string) *ristretto.Scalar {
	return hexToScalar(viewPrivate)
}

func (account *Account) SubaddressSpendPrivateKey(index uint64) *ristretto.Scalar {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:], index)
	var address ristretto.Scalar
	hash := blake2b.New512()
	hash.Write([]byte(SUBADDRESS_DOMAIN_TAG))
	hash.Write(account.ViewPrivateKey.Bytes())
	hash.Write(address.SetBytes(&buf).Bytes())

	var hs ristretto.Scalar
	var key [64]byte
	copy(key[:], hash.Sum(nil))

	var private ristretto.Scalar
	return private.Add(hs.SetReduced(&key), account.SpendPrivateKey)
}

func (account *Account) SubaddressViewPrivateKey(spend *ristretto.Scalar) *ristretto.Scalar {
	var private ristretto.Scalar
	return private.Mul(account.ViewPrivateKey, spend)
}

func (account *Account) B58Code(index uint64) (string, error) {
	spendPrivate := account.SubaddressSpendPrivateKey(index)
	spend := PublicKey(spendPrivate)
	view := PublicKey(account.SubaddressViewPrivateKey(spendPrivate))

	address := &block.PublicAddress{
		ViewPublicKey:  &block.CompressedRistretto{Data: view.Bytes()},
		SpendPublicKey: &block.CompressedRistretto{Data: spend.Bytes()},
	}
	wrapper := &block.PrintableWrapper_PublicAddress{PublicAddress: address}
	data, err := proto.Marshal(&block.PrintableWrapper{Wrapper: wrapper})
	if err != nil {
		return "", err
	}

	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, crc32.ChecksumIEEE(data))
	bytes = append(bytes, data...)
	return base58.Encode(bytes), nil
}

func B58CodeFromSpend(viewPrivate string, spend *ristretto.Scalar) (string, error) {
	account, err := NewAccountKey(viewPrivate, "")
	if err != nil {
		return "", err
	}
	view := PublicKey(account.SubaddressViewPrivateKey(spend))

	address := &block.PublicAddress{
		ViewPublicKey: &block.CompressedRistretto{
			Data: view.Bytes(),
		},
		SpendPublicKey: &block.CompressedRistretto{
			Data: spend.Bytes(),
		},
	}
	wrapper := &block.PrintableWrapper_PublicAddress{PublicAddress: address}
	data, err := proto.Marshal(&block.PrintableWrapper{Wrapper: wrapper})
	if err != nil {
		return "", err
	}

	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, crc32.ChecksumIEEE(data))
	bytes = append(bytes, data...)
	return base58.Encode(bytes), nil
}

func DecodeAccount(account string) (*PublicAddress, error) {
	data := base58.Decode(account)
	if len(data) < 4 {
		return nil, fmt.Errorf("Invalid account %s", account)
	}
	sum := make([]byte, 4)
	binary.LittleEndian.PutUint32(sum, crc32.ChecksumIEEE(data[4:]))
	if bytes.Compare(sum, data[:4]) != 0 {
		return nil, fmt.Errorf("Invalid account %s", account)
	}
	var wrapper block.PrintableWrapper
	err := proto.Unmarshal(data[4:], &wrapper)
	if err != nil {
		return nil, err
	}
	address := wrapper.GetPublicAddress()

	return &PublicAddress{
		ViewPublicKey:   hex.EncodeToString(address.GetViewPublicKey().GetData()),
		SpendPublicKey:  hex.EncodeToString(address.GetSpendPublicKey().GetData()),
		FogReportUrl:    address.GetFogReportUrl(),
		FogReportId:     address.GetFogReportId(),
		FogAuthoritySig: hex.EncodeToString(address.GetFogAuthoritySig()),
	}, nil
}

func PublicKey(private *ristretto.Scalar) *ristretto.Point {
	var point ristretto.Point
	return point.ScalarMultBase(private)
}

func SharedSecret(viewPrivate, publicKey string) *ristretto.Point {
	public := hexToPoint(publicKey)
	private := hexToScalar(viewPrivate)
	return createSharedSecret(public, private)
}

func createSharedSecret(public *ristretto.Point, private *ristretto.Scalar) *ristretto.Point {
	var r ristretto.Point
	return r.ScalarMult(public, private)
}

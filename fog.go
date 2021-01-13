package api

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/bwesterb/go-ristretto"
	"github.com/dchest/blake2b"
	"golang.org/x/crypto/hkdf"
)

const (
	MAJOR_VERSION        = 1
	LATEST_MINOR_VERSION = 0
)

func FakeFogHint() ([]byte, error) {
	var r ristretto.Scalar
	var p ristretto.Point
	p.ScalarMultBase(r.Rand())

	return encryptInPlaceDetached(&p)
}

// Footersize = 50, + 32 for one curve point, + 2 bytes of magic / padding space for future needs
func encryptInPlaceDetached(pub *ristretto.Point) ([]byte, error) {
	ourPublic, sharedSecret := newSecret(pub)
	curve_point_bytes := ourPublic.Bytes()

	//key & nonce of aes
	key, nonce, err := kdfStep(sharedSecret)
	if err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 34)
	ciphertext := aesgcm.Seal(nil, nonce, buf, nil)
	curve_point_bytes = append(curve_point_bytes, ciphertext[34:]...)
	curve_point_bytes = append(curve_point_bytes, MAJOR_VERSION)
	curve_point_bytes = append(curve_point_bytes, LATEST_MINOR_VERSION)
	curve_point_bytes = append(ciphertext[:34], curve_point_bytes...)
	return curve_point_bytes, err
}

// our public, shared_secret
func newSecret(pub *ristretto.Point) (*ristretto.Point, *ristretto.Point) {
	var r ristretto.Scalar
	r.Rand()

	var p ristretto.Point
	p.ScalarMultBase(&r)

	var share ristretto.Point
	return &p, share.PublicScalarMult(pub, &r)
}

/// This part must produce the key and IV/nonce for aes-gcm
func kdfStep(secret *ristretto.Point) ([]byte, []byte, error) {
	var okm [28]byte
	key := hkdf.New(blake2b.New512, secret.Bytes(), []byte("dei-salty-box"), []byte("aead-key-iv"))
	_, err := key.Read(okm[:])
	if err != nil {
		return nil, nil, err
	}
	return okm[:16], okm[16:], err
}

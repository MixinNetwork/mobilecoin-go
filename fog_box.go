package api

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/bwesterb/go-ristretto"
	"github.com/dchest/blake2b"
	"golang.org/x/crypto/hkdf"
)

// our public, shared_secret
func newSecret(pub *ristretto.Point) (*ristretto.Point, *ristretto.Point) {
	var r ristretto.Scalar
	r.Rand()

	var p ristretto.Point
	p.ScalarMultBase(&r)

	var share ristretto.Point
	return &p, share.ScalarMult(pub, &r)
}

/// This part must produce the key and IV/nonce for aes-gcm
func kdfStep(secret *ristretto.Point) ([]byte, []byte, error) {
	var okm [44]byte
	key := hkdf.New(blake2b.New512, secret.Bytes(), []byte("dei-salty-box"), []byte("aead-key-iv"))
	_, err := key.Read(okm[:])
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], err
}

func encryptInPlaceDetachedInAead(key, nonce, buffer []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, buffer, nil)
	var footer []byte
	footer = append(footer, ciphertext[len(buffer):]...)
	footer = append(footer, MAJOR_VERSION, LATEST_MINOR_VERSION)
	return footer, ciphertext[:len(buffer)], nil
}

// Footersize = 50, + 32 for one curve point, + 2 bytes of magic / padding space for future needs
func encryptInPlaceDetached(pub *ristretto.Point, buffer []byte) ([]byte, []byte, error) {
	// ECDH
	ourPublic, sharedSecret := newSecret(pub)
	curve_point_bytes := ourPublic.Bytes()

	// KDF key 32 & nonce 12 of aes Aes256Gcm
	aesKey, aesNonce, err := kdfStep(sharedSecret)
	if err != nil {
		return nil, nil, err
	}

	mac, buffer, err := encryptInPlaceDetachedInAead(aesKey, aesNonce, buffer)
	if err != nil {
		return nil, nil, err
	}

	curve_point_bytes = append(curve_point_bytes, mac...)
	return curve_point_bytes, buffer, nil
}

func encryptFixedLength(pub *ristretto.Point, buffer []byte) ([]byte, error) {
	footer, buffer, err := encryptInPlaceDetached(pub, buffer)
	if err != nil {
		return nil, err
	}
	return append(buffer, footer...), nil
}

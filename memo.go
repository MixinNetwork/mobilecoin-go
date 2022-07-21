package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/hkdf"
)

func EncryptMemo(plain string, public, private string) ([]byte, error) {
	secret := createSharedSecret(hexToPoint(public), hexToScalar(private))

	hash := sha512.New
	salt := []byte("mc-memo-okm")

	hkdf := hkdf.New(hash, secret.Bytes(), salt, []byte(""))
	key := make([]byte, 48)
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString(plain)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, key[32:])
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func DecryptMemo(text string, public, private string) ([]byte, error) {
	secret := createSharedSecret(hexToPoint(public), hexToScalar(private))

	hash := sha512.New
	salt := []byte("mc-memo-okm")

	hkdf := hkdf.New(hash, secret.Bytes(), salt, []byte(""))
	key := make([]byte, 48)
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, key[32:])
	plaintext := make([]byte, len(data))
	stream.XORKeyStream(plaintext, data)
	return plaintext, nil
}

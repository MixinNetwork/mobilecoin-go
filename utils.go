package api

import (
	"github.com/dchest/blake2b"
)

func ConfirmationNumberFromSecret(buf []byte) []byte {
	hash := blake2b.New256()
	hash.Write([]byte(TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG))
	hash.Write(buf)
	return hash.Sum(nil)
}

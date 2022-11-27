package api

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestUtils(t *testing.T) {
	buf, err := hex.DecodeString("")
	if err != nil {
		panic(err)
	}
	confirmation := ConfirmationNumberFromSecret(buf)
	log.Println(hex.EncodeToString(confirmation))
}

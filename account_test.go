package api

import (
	"log"
	"testing"
)

func TestAccount(t *testing.T) {
	account, err := DecodeAccount("test")
	log.Println(err)
	log.Printf("%#v", account)
}

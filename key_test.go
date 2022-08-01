package api

import (
	"encoding/hex"
	"log"
	"testing"

	account "github.com/jadeydi/mobilecoin-account"
	"github.com/stretchr/testify/assert"
)

func TestTargetKey(t *testing.T) {
	assert := assert.New(t)

	privateV := "367ce216ecd113cd6ed49d52f4c9df63d0818ed941e72170419a70c8ec1bcd0c"
	privateS := "62afd57ca5394ce7e57323c0925af72cabad4c3b42cf9a6c6403ee9c5227740a"

	acc := &account.Account{
		ViewPrivateKey:  account.HexToScalar(privateV),
		SpendPrivateKey: account.HexToScalar(privateS),
	}

	spendPrivate := acc.SubaddressSpendPrivateKey(0)
	log.Println("SubaddressSpendPrivateKey spend 0:", hex.EncodeToString(spendPrivate.Bytes()))

	acc, err := account.NewAccountKey(privateV, privateS)
	assert.Nil(err)
	spendPrivate = acc.SubaddressSpendPrivateKey(0)
	log.Println("SubaddressSpendPrivateKey spend 00:", hex.EncodeToString(spendPrivate.Bytes()))

	spend := account.PublicKey(spendPrivate)
	view := account.PublicKey(acc.SubaddressViewPrivateKey(spendPrivate))
	log.Println("spend:", hex.EncodeToString(spend.Bytes()))
	log.Println("view:", hex.EncodeToString(view.Bytes()))

	random := account.HexToScalar("98e5c5483a38efd8731c906e0e850bc258dbd12751145a82590ee71f0c274e0e")
	recipient := &account.PublicAddress{
		ViewPublicKey:  hex.EncodeToString(view.Bytes()),
		SpendPublicKey: hex.EncodeToString(spend.Bytes()),
	}
	target := createOnetimePublicKey(random, recipient)
	// 7819529cc83ed09fb734fb0709fbd73ba19594c7789cf1ecb12ffc7d7a79fc58
	log.Println("target:::", hex.EncodeToString(target.Bytes()))
	public := createTxPublicKey(random, spend)
	log.Println("public:::", hex.EncodeToString(public.Bytes()))

	spendPrivate = acc.SubaddressSpendPrivateKey(0)
	onetime, err := RecoverOnetimePrivateKey(hex.EncodeToString(public.Bytes()), privateV+privateS)
	assert.Nil(err)
	log.Println("onetime::", hex.EncodeToString(onetime.Bytes()))
	assert.Equal(hex.EncodeToString(account.PublicKey(onetime).Bytes()), hex.EncodeToString(target.Bytes()))
}

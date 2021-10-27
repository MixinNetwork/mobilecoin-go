package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"testing"

	"github.com/jadeydi/mobilecoin-account/block"
	"github.com/stretchr/testify/assert"
)

func TestHashOfReport(t *testing.T) {
	assert := assert.New(t)

	reports := []*block.Report{
		&block.Report{
			FogReportId: "id",
			Report: &block.VerificationReport{
				Sig: &block.VerificationSignature{
					Contents: []byte{},
				},
				Chain:    [][]byte{},
				HttpBody: "this should probably be a json",
			},
			PubkeyExpiry: 0,
		},
	}
	log.Println(hex.EncodeToString(HashOfReport(reports)))

	buf, err := hex.DecodeString("e21eb8c9cf3e2b725904dc1b544feeea7ad4dcc93235eb51aeb7a6c1ef99cc02")
	assert.Nil(err)
	private := ed25519.NewKeyFromSeed(buf)
	log.Println("private", hex.EncodeToString(private))

	sig := ed25519.Sign(private, HashOfReport(reports))
	log.Println("sig", hex.EncodeToString(sig))
	public := private.Public().(ed25519.PublicKey)
	assert.True(ed25519.Verify(public, HashOfReport(reports), sig))
}

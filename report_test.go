package api

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/MixinNetwork/mobilecoin-go/block"
)

func TestHashOfReport(t *testing.T) {
	reports := []*block.Report{
		&block.Report{
			FogReportId: "id",
			Report: &block.VerificationReport{
				Sig: &block.VerificationSignature{
					Contents: []byte{},
				},
				Chain:    [][]byte{[]byte{0, 5}},
				HttpBody: "this should probably be a json",
			},
			PubkeyExpiry: 0,
		},
	}
	log.Println(hex.EncodeToString(HashOfReport(reports)))
}

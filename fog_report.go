package api

import (
	"crypto/ed25519"

	"github.com/MixinNetwork/mobilecoin-go/block"
)

func VerifyReports(public ed25519.PublicKey, reports []block.Report, sig []byte) {
}

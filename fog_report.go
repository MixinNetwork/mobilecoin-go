package api

import (
	"crypto/ed25519"
	"errors"

	"github.com/jadeydi/mobilecoin-account/types"
)

// https://github.com/mobilecoinfoundation/mobilecoin/blob/2f90154a445c769594dfad881463a2d4a003d7d6/fog/sig/src/public_address.rs#L56
func VerifyReports(public ed25519.PublicKey, reports []*types.Report, sig []byte) error {
	b := ed25519.Verify(public, HashOfReport(reports), sig)
	if !b {
		return errors.New("Report Error")
	}
	return nil
}

// https://github.com/mobilecoinfoundation/mobilecoin/blob/2f90154a445c769594dfad881463a2d4a003d7d6/fog/report/validation/src/ingest_report.rs#L23
func ValidateIngestIASReport(report *types.VerificationReport) {
}

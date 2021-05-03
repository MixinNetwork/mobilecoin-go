package api

import (
	_ "embed"
)

//go:embed credentials/AttestationReportSigningCACert.pem
var AttestationReportSigningCACert []byte

//go:embed credentials/Dev_AttestationReportSigningCACert.pem
var Dev_AttestationReportSigningCACert []byte

//go:embed credentials/root_anchor.pem
var root_anchor []byte

//go:embed credentials/chain.pem
var chain []byte

//go:embed credentials/signer.key
var signer []byte

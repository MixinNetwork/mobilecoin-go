package api

import (
	"github.com/gtank/merlin"
	"github.com/jadeydi/mobilecoin-account/types"
)

func HashOfReport(reports []*types.Report) []byte {
	t := merlin.NewTranscript("digestible")
	appendReports(reports, t)
	return t.ExtractBytes([]byte("digest32"), 32)
}

func appendFogReportId(body string, t *merlin.Transcript) {
	appendBytes([]byte("fog_report_id"), []byte(PRIMITIVE), t)
	appendBytes([]byte("str"), []byte(body), t)
}

func appendSig(sig *types.VerificationSignature, t *merlin.Transcript) {
	appendBytes([]byte("sig"), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("VerificationSignature"), t)
	appendBytes([]byte("0"), []byte("prim"), t)
	appendBytes([]byte("bytes"), sig.GetContents(), t)
	appendBytes([]byte("sig"), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("VerificationSignature"), t)
}

func appendChains(chains [][]byte, t *merlin.Transcript) {
	appendBytes([]byte("chain"), []byte("seq"), t)
	appendInt64("len", uint64(len(chains)), t)
	for _, chain := range chains {
		appendBytes([]byte(""), []byte("prim"), t)
		appendBytes([]byte("bytes"), chain, t)
	}
}

func appendHttpBody(body string, t *merlin.Transcript) {
	appendBytes([]byte("http_body"), []byte(PRIMITIVE), t)
	appendBytes([]byte("str"), []byte(body), t)
}

func appendVerificationReport(report *types.VerificationReport, t *merlin.Transcript) {
	appendBytes([]byte("report"), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("VerificationReport"), t)
	appendSig(report.GetSig(), t)
	if len(report.GetChain()) > 0 {
		appendChains(report.GetChain(), t)
	}
	appendHttpBody(report.GetHttpBody(), t)
	appendBytes([]byte("report"), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("VerificationReport"), t)
}

func appendPubkeyExpiry(expiry uint64, t *merlin.Transcript) {
	appendBytes([]byte("pubkey_expiry"), []byte(PRIMITIVE), t)
	appendInt64("uint", expiry, t)
}

func appendReport(report *types.Report, t *merlin.Transcript) {
	appendBytes([]byte(""), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("Report"), t)
	appendFogReportId(report.FogReportId, t)
	appendVerificationReport(report.GetReport(), t)
	appendPubkeyExpiry(report.GetPubkeyExpiry(), t)
	appendBytes([]byte(""), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("Report"), t)
}

func appendReports(reports []*types.Report, t *merlin.Transcript) {
	appendBytes([]byte("Fog ingest reports"), []byte(SEQUENCE), t)
	appendInt64("len", uint64(len(reports)), t)
	for _, report := range reports {
		appendReport(report, t)
	}
}

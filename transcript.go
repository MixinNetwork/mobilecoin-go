package api

import (
	"github.com/gtank/merlin"
)

// should use BULLETPROOF_DOMAIN_TAG
func InitialTranscript(label string) *merlin.Transcript {
	return merlin.NewTranscript(label)
}

func RangeproofDomainSep(n int64, m int64, t *merlin.Transcript) *merlin.Transcript {
	appendBytes([]byte("dom-sep"), []byte("rangeproof v1"), t)

	appendInt64("n", uint64(n), t)
	appendInt64("m", uint64(m), t)
	return t
}

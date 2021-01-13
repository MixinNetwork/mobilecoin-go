package api

import "github.com/bwesterb/go-ristretto"

type BitCommitment struct {
	VJ *ristretto.Point // equal V_j: CompressedRistretto
	AJ *ristretto.Point
	SJ *ristretto.Point
}

type BitChallenge struct {
	Y *ristretto.Scalar
	Z *ristretto.Scalar
}

type PolyChallenge struct {
	X *ristretto.Scalar
}

type PolyCommitment struct {
	T1j *ristretto.Point
	T2j *ristretto.Point
}

type ProofShare struct {
	TX         *ristretto.Scalar
	TXBlinding *ristretto.Scalar
	EBlinding  *ristretto.Scalar
	LVec       []*ristretto.Scalar
	RVec       []*ristretto.Scalar
}

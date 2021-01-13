package api

import (
	"errors"
	"fmt"

	"github.com/bwesterb/go-ristretto"
)

type PartyAwaitingPosition struct {
	BPGens    *BulletproofGens
	PCGens    *PedersenGens
	N         int64
	Value     uint64
	VBlinding *ristretto.Scalar
	V         *ristretto.Point
}

func NewParty(bg *BulletproofGens, pg *PedersenGens, value uint64, blinding *ristretto.Scalar, n int64) *PartyAwaitingPosition {
	switch n {
	case 8, 16, 32, 64:
	default:
		panic(fmt.Errorf("NewParty InvalidBitsize %d", n))
	}
	if bg.GensCapacity < n {
		panic(fmt.Errorf("NewParty InvalidGeneratorsLength %d, %d", bg.GensCapacity, n))
	}

	V := pg.Commit(uint64ToScalar(value), blinding)

	return &PartyAwaitingPosition{
		BPGens:    bg,
		PCGens:    pg,
		N:         n,
		Value:     value,
		VBlinding: blinding,
		V:         V,
	}
}

type PartyAwaitingBitChallenge struct {
	N         int64
	V         uint64
	VBlinding *ristretto.Scalar
	J         int
	PCGens    *PedersenGens
	ABlinding *ristretto.Scalar
	SBlinding *ristretto.Scalar
	SL        []*ristretto.Scalar
	SR        []*ristretto.Scalar
}

func (p *PartyAwaitingPosition) AssignPositionWithRNG(j int) (*PartyAwaitingBitChallenge, *BitCommitment, error) {
	if p.BPGens.PartyCapacity <= int64(j) {
		return nil, nil, fmt.Errorf("AssignPositionWithRNG InvalidGeneratorsLength %d, %d", p.BPGens.PartyCapacity, j)
	}
	bpShare := p.BPGens.Share(j)

	var aBlinding ristretto.Scalar
	aBlinding.Rand()
	var A ristretto.Point
	A.ScalarMult(p.PCGens.BBlinding, &aBlinding)

	// If v_i = 0, we add a_L[i] * G[i] + a_R[i] * H[i] = - H[i]
	// If v_i = 1, we add a_L[i] * G[i] + a_R[i] * H[i] =   G[i]
	Gs := bpShare.G(p.N)
	Hs := bpShare.H(p.N)

	for i := range Gs {
		var point ristretto.Point
		point.Neg(Hs[i])

		v_i := (p.Value >> i) & 1
		if v_i == 1 {
			point = *Gs[i]
		}
		A.Add(&A, &point)
	}

	var sBlinding ristretto.Scalar
	sBlinding.Rand()

	sL := make([]*ristretto.Scalar, p.N)
	sR := make([]*ristretto.Scalar, p.N)
	for i := 0; i < int(p.N); i++ {
		var s1, s2 ristretto.Scalar
		sL[i] = s1.Rand()
		sR[i] = s2.Rand()
	}

	// Compute S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
	s1 := append([]*ristretto.Scalar{&sBlinding}, sL...)
	s1 = append(s1, sR...)
	s2 := append([]*ristretto.Point{p.PCGens.BBlinding}, Gs...)
	s2 = append(s2, Hs...)
	S := multiscalarMul(s1, s2)

	bitCommitment := &BitCommitment{
		VJ: p.V,
		AJ: &A,
		SJ: S,
	}

	nextState := &PartyAwaitingBitChallenge{
		N:         p.N,
		V:         p.Value,
		VBlinding: p.VBlinding,
		PCGens:    p.PCGens,
		J:         j,
		ABlinding: &aBlinding,
		SBlinding: &sBlinding,
		SL:        sL,
		SR:        sR,
	}
	return nextState, bitCommitment, nil
}

func (p *PartyAwaitingBitChallenge) ApplyChallengeWithRNG(vc *BitChallenge) (*PartyAwaitingPolyChallenge, *PolyCommitment) {
	OffsetY := ScalarExpVartime(vc.Y, uint64(int64(p.J)*p.N))
	OffsetZ := ScalarExpVartime(vc.Z, uint64(p.J))

	LPoly := ZeroVecPoly1(p.N)
	RPoly := ZeroVecPoly1(p.N)

	var OffsetZZ ristretto.Scalar
	OffsetZZ.Mul(vc.Z, vc.Z)
	OffsetZZ.Mul(&OffsetZZ, OffsetZ)

	expY := OffsetY
	var exp2 ristretto.Scalar
	exp2.SetOne()

	for i := 0; i < int(p.N); i++ {
		a_L_i := uint64ToScalar(uint64((p.V >> i) & 1))
		var one, a_R_i ristretto.Scalar
		one.SetOne()
		a_R_i.Sub(a_L_i, &one)

		LPoly.As[i].Sub(a_L_i, vc.Z)
		LPoly.Bs[i] = p.SL[i]

		var tmp1, tmp2 ristretto.Scalar
		tmp1.Add(&a_R_i, vc.Z)
		tmp1.Mul(expY, &tmp1)
		tmp2.Mul(&OffsetZZ, &exp2)
		RPoly.As[i].Add(&tmp1, &tmp2)
		RPoly.Bs[i].Mul(expY, p.SR[i])

		expY.Mul(expY, vc.Y)
		exp2.Add(&exp2, &exp2)
	}

	tPoly := LPoly.InnerProduct(RPoly)

	var t1blinding, t2blinding ristretto.Scalar
	t1blinding.Rand()
	t2blinding.Rand()

	T1 := p.PCGens.Commit(tPoly.B, &t1blinding)
	T2 := p.PCGens.Commit(tPoly.C, &t2blinding)

	poly_commitment := &PolyCommitment{
		T1j: T1,
		T2j: T2,
	}

	papc := &PartyAwaitingPolyChallenge{
		OffsetZZ:   &OffsetZZ,
		LPoly:      LPoly,
		RPoly:      RPoly,
		TPoly:      tPoly,
		T1Blinding: &t1blinding,
		T2Blinding: &t2blinding,
		VBlinding:  p.VBlinding,
		ABlinding:  p.ABlinding,
		SBlinding:  p.SBlinding,
	}
	return papc, poly_commitment
}

func innerProduct(a []*ristretto.Scalar, b []*ristretto.Scalar) *ristretto.Scalar {
	if len(a) != len(b) {
		panic(fmt.Sprintf("innerProduct lengths of vectors do not match %d, %d", len(a), len(b)))
	}

	var zero ristretto.Scalar
	zero.SetZero()
	for i := range a {
		var r ristretto.Scalar
		zero.Add(&zero, r.Mul(a[i], b[i]))
	}
	return &zero
}

func addVec(a []*ristretto.Scalar, b []*ristretto.Scalar) []*ristretto.Scalar {
	if len(a) != len(b) {
		panic(fmt.Sprintf("addVec lengths of vectors do not match %d, %d", len(a), len(b)))
	}

	out := make([]*ristretto.Scalar, len(a))
	for i := range a {
		var r ristretto.Scalar
		out[i] = r.Add(a[i], b[i])
	}
	return out
}

type PartyAwaitingPolyChallenge struct {
	OffsetZZ   *ristretto.Scalar
	LPoly      *VecPoly1
	RPoly      *VecPoly1
	TPoly      *Poly2
	VBlinding  *ristretto.Scalar
	ABlinding  *ristretto.Scalar
	SBlinding  *ristretto.Scalar
	T1Blinding *ristretto.Scalar
	T2Blinding *ristretto.Scalar
}

func (p *PartyAwaitingPolyChallenge) ApplyChallenge(pc *PolyChallenge) (*ProofShare, error) {
	var zero ristretto.Scalar
	zero.SetZero()
	if zero.Equals(pc.X) {
		return nil, errors.New("MaliciousDealer")
	}

	var a ristretto.Scalar
	a.Mul(p.OffsetZZ, p.VBlinding)
	tBlindingPoly := Poly2{
		A: &a,
		B: p.T1Blinding,
		C: p.T2Blinding,
	}

	tx := p.TPoly.Eval(pc.X)
	txBlinding := tBlindingPoly.Eval(pc.X)
	var eBlinding ristretto.Scalar
	eBlinding.Mul(p.SBlinding, pc.X)
	eBlinding.Add(p.ABlinding, &eBlinding)
	lVec := p.LPoly.Eval(pc.X)
	rVec := p.RPoly.Eval(pc.X)

	return &ProofShare{
		TXBlinding: txBlinding,
		TX:         tx,
		EBlinding:  &eBlinding,
		LVec:       lVec,
		RVec:       rVec,
	}, nil
}

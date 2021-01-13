package api

import (
	"fmt"
	"math/bits"

	"github.com/bwesterb/go-ristretto"
	"github.com/gtank/merlin"
)

// N is Create a 64-bit RangeProof and corresponding commitments.
// M is the length of values
type DealerAwaitingBitCommitments struct {
	BPGens            *BulletproofGens
	PCGens            *PedersenGens
	Transcript        *merlin.Transcript
	InitialTranscript *merlin.Transcript
	N, M              int64
}

func NewDealer(bg *BulletproofGens, pg *PedersenGens, initial, t *merlin.Transcript, n, m int64) *DealerAwaitingBitCommitments {
	switch n {
	case 8, 16, 32, 64:
	default:
		panic(fmt.Errorf("NewDealer InvalidBitsize n: %d", n))
	}
	if bits.OnesCount64(uint64(m)) > 1 {
		panic(fmt.Errorf("NewDealer InvalidAggregation m: %d", m))
	}
	if bg.GensCapacity < n {
		panic(fmt.Errorf("NewDealer InvalidGeneratorsLength GensCapacity %d, n %d", bg.GensCapacity, n))
	}
	if bg.PartyCapacity < m {
		panic(fmt.Errorf("NewDealer InvalidGeneratorsLength PartyCapacity %d, m %d", bg.PartyCapacity, m))
	}

	t = RangeproofDomainSep(n, m, t)

	return &DealerAwaitingBitCommitments{
		BPGens:            bg,
		PCGens:            pg,
		Transcript:        t,
		InitialTranscript: initial,
		N:                 n,
		M:                 m,
	}
}

type DealerAwaitingPolyCommitments struct {
	N, M              int64
	Transcript        *merlin.Transcript
	InitialTranscript *merlin.Transcript
	BPGens            *BulletproofGens
	PCGens            *PedersenGens
	BitChallenge      *BitChallenge
	BitCommitments    []*BitCommitment
	A                 *ristretto.Point
	S                 *ristretto.Point
}

func (d *DealerAwaitingBitCommitments) ReceiveBitCommitments(commitments []*BitCommitment) (*DealerAwaitingPolyCommitments, *BitChallenge, error) {
	if int(d.M) != len(commitments) {
		return nil, nil, fmt.Errorf("ReceiveBitCommitments WrongNumBitCommitments %d %d", int(d.M), len(commitments))
	}

	var A, S ristretto.Point
	A.SetZero()
	S.SetZero()
	for i, _ := range commitments {
		d.Transcript.AppendMessage([]byte("V"), commitments[i].VJ.Bytes())
		A.Add(&A, commitments[i].AJ)
		S.Add(&S, commitments[i].SJ)
	}
	d.Transcript.AppendMessage([]byte("A"), A.Bytes())
	d.Transcript.AppendMessage([]byte("S"), S.Bytes())

	y := ChallengeScalar("y", d.Transcript)
	z := ChallengeScalar("z", d.Transcript)
	challenge := &BitChallenge{Y: y, Z: z}

	return &DealerAwaitingPolyCommitments{
		N:                 d.N,
		M:                 d.M,
		Transcript:        d.Transcript,
		InitialTranscript: d.InitialTranscript,
		BPGens:            d.BPGens,
		PCGens:            d.PCGens,
		BitChallenge:      challenge,
		BitCommitments:    commitments,
		A:                 &A,
		S:                 &S,
	}, challenge, nil
}

func (p *DealerAwaitingPolyCommitments) ReceivePolyCommitments(commitments []*PolyCommitment) (*DealerAwaitingProofShares, *PolyChallenge) {
	if int(p.M) != len(commitments) {
		panic(fmt.Sprintf("ReceivePolyCommitments WrongNumPolyCommitments %d %d", p.M, len(commitments)))
	}

	var T1, T2 ristretto.Point
	T1.SetZero()
	T2.SetZero()
	for i := range commitments {
		T1.Add(&T1, commitments[i].T1j)
		T2.Add(&T2, commitments[i].T2j)
	}
	p.Transcript.AppendMessage([]byte("T_1"), T1.Bytes())
	p.Transcript.AppendMessage([]byte("T_2"), T2.Bytes())

	x := ChallengeScalar("x", p.Transcript)
	poly_challenge := &PolyChallenge{X: x}
	share := &DealerAwaitingProofShares{
		N:                 p.N,
		M:                 p.M,
		Transcript:        p.Transcript,
		InitialTranscript: p.InitialTranscript,
		BPGens:            p.BPGens,
		PCGens:            p.PCGens,
		BitChallenge:      p.BitChallenge,
		BitCommitments:    p.BitCommitments,
		A:                 p.A,
		S:                 p.S,
		PolyChallenge:     poly_challenge,
		PolyCommitments:   commitments,
		T1:                &T1,
		T2:                &T2,
	}
	return share, poly_challenge
}

type DealerAwaitingProofShares struct {
	N, M              int64
	Transcript        *merlin.Transcript
	InitialTranscript *merlin.Transcript
	BPGens            *BulletproofGens
	PCGens            *PedersenGens
	BitChallenge      *BitChallenge
	BitCommitments    []*BitCommitment
	A                 *ristretto.Point
	S                 *ristretto.Point
	PolyChallenge     *PolyChallenge
	PolyCommitments   []*PolyCommitment
	T1, T2            *ristretto.Point
}

func (ps *ProofShare) checkSize(n int64, bp_gens *BulletproofGens, j int) error {
	if len(ps.LVec) != int(n) {
		return fmt.Errorf("checkSize error 0: %d, %d", len(ps.LVec), n)
	}
	if len(ps.RVec) != int(n) {
		return fmt.Errorf("checkSize error 1 %d, %d", len(ps.RVec), n)
	}
	if n > bp_gens.GensCapacity {
		return fmt.Errorf("checkSize error 2 %d, %d", n, bp_gens.GensCapacity)
	}
	if int64(j) >= bp_gens.GensCapacity {
		return fmt.Errorf("checkSize error 3 %d, %d", j, bp_gens.GensCapacity)
	}
	return nil
}

func (d *DealerAwaitingProofShares) AssembleShares(proofs []*ProofShare) *RangeProof {
	if int(d.M) != len(proofs) {
		panic(fmt.Sprintf("AssembleShares WrongNumProofShares %d %d", d.M, len(proofs)))
	}

	var badShares []int
	for i, p := range proofs {
		if err := p.checkSize(d.N, d.BPGens, i); err != nil {
			badShares = append(badShares, i)
		}
	}
	if len(badShares) > 0 {
		panic(fmt.Sprintf("MalformedProofShares bad shares %#v", badShares))
	}

	var tx, tx_blinding, e_blinding ristretto.Scalar
	tx.SetZero()
	tx_blinding.SetZero()
	e_blinding.SetZero()
	for i, _ := range proofs {
		tx.Add(&tx, proofs[i].TX)
		tx_blinding.Add(&tx_blinding, proofs[i].TXBlinding)
		e_blinding.Add(&e_blinding, proofs[i].EBlinding)
	}

	appendScalar("t_x", &tx, d.Transcript)
	appendScalar("t_x_blinding", &tx_blinding, d.Transcript)
	appendScalar("e_blinding", &e_blinding, d.Transcript)

	w := ChallengeScalar("w", d.Transcript)
	var Q ristretto.Point
	Q.ScalarMult(d.PCGens.B, w)

	GFactors := make([]*ristretto.Scalar, d.N*d.M)
	HFactors := make([]*ristretto.Scalar, d.N*d.M)
	var inverseY ristretto.Scalar
	inverseY.Inverse(d.BitChallenge.Y)
	/// exp_iter Return an iterator of the powers of `x`.
	scalarExp := NewScalarExp(&inverseY)

	for i := 0; i < int(d.N*d.M); i++ {
		var one ristretto.Scalar
		GFactors[i] = one.SetOne()
		HFactors[i] = scalarExp.Next()
	}

	var LVec, RVec []*ristretto.Scalar
	for i := range proofs {
		for j := range proofs[i].LVec {
			var zero ristretto.Scalar
			zero.SetZero()
			LVec = append(LVec, zero.Add(&zero, proofs[i].LVec[j])) // clone
		}
		for j := range proofs[i].RVec {
			var zero ristretto.Scalar
			zero.SetZero()
			RVec = append(RVec, zero.Add(&zero, proofs[i].RVec[j]))
		}
	}

	G := d.BPGens.G(d.N, d.M)
	H := d.BPGens.H(d.N, d.M)
	n := len(GFactors)
	gVec, hVec := make([]*ristretto.Point, n), make([]*ristretto.Point, n)
	for i := 0; i < n; i++ {
		var z0, z1 ristretto.Point
		z0.SetZero()
		z1.SetZero()
		gVec[i] = z0.Add(&z0, G.Next()) // clone
		hVec[i] = z1.Add(&z1, H.Next())
	}
	ippProof := CreateInnerProductProof(d.Transcript, &Q, GFactors, HFactors, gVec, hVec, LVec, RVec)

	return &RangeProof{
		A:          d.A,
		S:          d.S,
		T1:         d.T1,
		T2:         d.T2,
		TX:         &tx,
		TXBlinding: &tx_blinding,
		EBlinding:  &e_blinding,
		IPPProof:   ippProof,
	}
}

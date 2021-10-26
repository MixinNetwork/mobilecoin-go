package api

import (
	"fmt"
	"math/bits"

	"github.com/bwesterb/go-ristretto"
	"github.com/gtank/merlin"
)

type InnerProductProof struct {
	LVec []*ristretto.Point
	RVec []*ristretto.Point
	A, B *ristretto.Scalar
}

func CreateInnerProductProof(transcript *merlin.Transcript, Q *ristretto.Point, gFactors, hFactors []*ristretto.Scalar, gVec, hVec []*ristretto.Point, aVec, bVec []*ristretto.Scalar) *InnerProductProof {
	n := len(gVec)

	if len(gVec) != n ||
		len(hVec) != n ||
		len(aVec) != n ||
		len(bVec) != n ||
		len(gFactors) != n ||
		len(hFactors) != n {
		panic(fmt.Sprintf("Invalid input vectors %d, %d, %d, %d, %d, %d", len(gVec), len(hVec), len(aVec), len(bVec), len(gFactors), len(hFactors)))
	}

	G := gVec
	H := hVec
	a := aVec
	b := bVec

	if bits.OnesCount32(uint32(n)) > 1 {
		panic(fmt.Sprintf("CreateInnerProductProof Invalid n %d", n))
	}

	InnerproductDomainSep(uint64(n), transcript)

	//lgN := bits.TrailingZeros64(uint64(n << 1))
	var LVec, RVec []*ristretto.Point

	if n != 1 {
		n = n / 2
		aL, aR := a[:n], a[n:]
		bL, bR := b[:n], b[n:]
		gL, gR := G[:n], G[n:]
		hL, hR := H[:n], H[n:]

		cL := innerProduct(aL, bR)
		cR := innerProduct(aR, bL)

		// vartime_multiscalar_mul begin
		chainAL := make([]*ristretto.Scalar, n)
		for i := range aL {
			var r ristretto.Scalar
			chainAL[i] = r.Mul(aL[i], gFactors[n+i])
		}
		for i := range bR {
			var r ristretto.Scalar
			chainAL = append(chainAL, r.Mul(bR[i], hFactors[i]))
		}
		chainAL = append(chainAL, cL)

		chainGR := make([]*ristretto.Point, 0)
		chainGR = append(chainGR, gR...)
		chainGR = append(chainGR, hL...)
		chainGR = append(chainGR, Q)

		L := vartimeMultiscalarMul(chainAL, chainGR)
		// vartime_multiscalar_mul end

		// vartime_multiscalar_mul begin
		chainAR := make([]*ristretto.Scalar, n)
		for i := range aR {
			var r ristretto.Scalar
			chainAR[i] = r.Mul(aR[i], gFactors[i])
		}
		for i := range bL {
			var r ristretto.Scalar
			chainAR = append(chainAR, r.Mul(bL[i], hFactors[n+i]))
		}
		chainAR = append(chainAR, cR)

		chainGL := make([]*ristretto.Point, 0)
		chainGL = append(chainGL, gL...)
		chainGL = append(chainGL, hR...)
		chainGL = append(chainGL, Q)
		R := vartimeMultiscalarMul(chainAR, chainGL)
		// vartime_multiscalar_mul end

		LVec = append(LVec, L)
		RVec = append(RVec, R)

		AppendPoint("L", L, transcript)
		AppendPoint("R", R, transcript)

		u := ChallengeScalar("u", transcript)
		var uInv ristretto.Scalar
		uInv.Inverse(u)

		for i := 0; i < n; i++ {
			var r1, r2 ristretto.Scalar
			aL[i].Add(r1.Mul(aL[i], u), r2.Mul(&uInv, aR[i]))
			var r3, r4 ristretto.Scalar
			bL[i].Add(r3.Mul(bL[i], &uInv), r4.Mul(u, bR[i]))
			var r5, r6 ristretto.Scalar
			r5.Mul(&uInv, gFactors[i])
			r6.Mul(u, gFactors[n+i])
			gL[i] = vartimeMultiscalarMul([]*ristretto.Scalar{&r5, &r6}, []*ristretto.Point{gL[i], gR[i]})
			var r7, r8 ristretto.Scalar
			r7.Mul(u, hFactors[i])
			r8.Mul(&uInv, hFactors[n+i])
			hL[i] = vartimeMultiscalarMul([]*ristretto.Scalar{&r7, &r8}, []*ristretto.Point{hL[i], hR[i]})
		}

		a = aL
		b = bL
		G = gL
		H = hL
	}

	for {
		if n == 1 {
			break
		}
		n = n / 2

		aL, aR := a[:n], a[n:]
		bL, bR := b[:n], b[n:]
		gL, gR := G[:n], G[n:]
		hL, hR := H[:n], H[n:]

		cL := innerProduct(aL, bR)
		cR := innerProduct(aR, bL)

		chainAL := make([]*ristretto.Scalar, 0)
		chainAL = append(chainAL, aL...)
		chainAL = append(chainAL, bR...)
		chainAL = append(chainAL, cL)
		chainGR := make([]*ristretto.Point, 0)
		chainGR = append(chainGR, gR...)
		chainGR = append(chainGR, hL...)
		chainGR = append(chainGR, Q)
		L := vartimeMultiscalarMul(chainAL, chainGR)

		chainAR := make([]*ristretto.Scalar, 0)
		chainAR = append(chainAR, aR...)
		chainAR = append(chainAR, bL...)
		chainAR = append(chainAR, cR)
		chainGL := make([]*ristretto.Point, 0)
		chainGL = append(chainGL, gL...)
		chainGL = append(chainGL, hR...)
		chainGL = append(chainGL, Q)
		R := vartimeMultiscalarMul(chainAR, chainGL)

		LVec = append(LVec, L)
		RVec = append(RVec, R)
		AppendPoint("L", L, transcript)
		AppendPoint("R", R, transcript)

		u := ChallengeScalar("u", transcript)
		var uInv ristretto.Scalar
		uInv.Inverse(u)

		for i := 0; i < n; i++ {
			var r1, r2 ristretto.Scalar
			aL[i].Add(r1.Mul(aL[i], u), r2.Mul(&uInv, aR[i]))
			var r3, r4 ristretto.Scalar
			bL[i].Add(r3.Mul(bL[i], &uInv), r4.Mul(u, bR[i]))
			gL[i] = vartimeMultiscalarMul([]*ristretto.Scalar{&uInv, u}, []*ristretto.Point{gL[i], gR[i]})
			hL[i] = vartimeMultiscalarMul([]*ristretto.Scalar{u, &uInv}, []*ristretto.Point{hL[i], hR[i]})
		}

		a = aL
		b = bL
		G = gL
		H = hL

	}

	return &InnerProductProof{
		LVec: LVec,
		RVec: RVec,
		A:    a[0],
		B:    b[0],
	}
}

func (p *InnerProductProof) ToBytes() []byte {
	var buf []byte

	for i := range p.LVec {
		buf = append(buf, p.LVec[i].Bytes()...)
		buf = append(buf, p.RVec[i].Bytes()...)
	}
	buf = append(buf, p.A.Bytes()...)
	buf = append(buf, p.B.Bytes()...)

	return buf
}

func vartimeMultiscalarMul(scalars []*ristretto.Scalar, points []*ristretto.Point) *ristretto.Point {
	var r ristretto.Point
	r.SetZero()
	for i := range scalars {
		var rr ristretto.Point
		rr.ScalarMult(points[i], scalars[i])
		r.Add(&r, &rr)
	}
	return &r
}

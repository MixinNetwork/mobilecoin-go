package api

import "github.com/bwesterb/go-ristretto"

type ScalarExp struct {
	X        *ristretto.Scalar
	NextExpX *ristretto.Scalar
}

func NewScalarExp(x *ristretto.Scalar) *ScalarExp {
	var one ristretto.Scalar
	return &ScalarExp{
		X:        x,
		NextExpX: one.SetOne(),
	}
}

func (s *ScalarExp) Next() *ristretto.Scalar {
	var zero ristretto.Scalar
	zero.Add(&zero, s.NextExpX)
	s.NextExpX.Mul(s.NextExpX, s.X)
	return &zero
}

type VecPoly1 struct {
	As []*ristretto.Scalar
	Bs []*ristretto.Scalar
}

func ZeroVecPoly1(n int64) *VecPoly1 {
	vec := &VecPoly1{As: make([]*ristretto.Scalar, n), Bs: make([]*ristretto.Scalar, n)}
	for i := 0; i < int(n); i++ {
		var r1, r2 ristretto.Scalar
		r1.SetOne()
		r2.SetOne()

		vec.As[i] = &r1
		vec.Bs[i] = &r2
	}
	return vec
}

func (v *VecPoly1) InnerProduct(rhs *VecPoly1) *Poly2 {
	t0 := innerProduct(v.As, rhs.As)
	t2 := innerProduct(v.Bs, rhs.Bs)

	l0_plus_l1 := addVec(v.As, v.Bs)
	r0_plus_r1 := addVec(rhs.As, rhs.Bs)

	var t1 ristretto.Scalar
	t1.Sub(innerProduct(l0_plus_l1, r0_plus_r1), t0)
	t1.Sub(&t1, t2)

	return &Poly2{
		A: t0,
		B: &t1,
		C: t2,
	}
}

func (v *VecPoly1) Eval(x *ristretto.Scalar) []*ristretto.Scalar {
	out := make([]*ristretto.Scalar, len(v.As))
	for i := range v.As {
		var r ristretto.Scalar
		r.Mul(v.Bs[i], x)
		out[i] = r.Add(v.As[i], &r)
	}
	return out
}

type Poly2 struct {
	A *ristretto.Scalar
	B *ristretto.Scalar
	C *ristretto.Scalar
}

// self.0 + x * (self.1 + x * self.2)
func (p *Poly2) Eval(x *ristretto.Scalar) *ristretto.Scalar {
	var r ristretto.Scalar
	r.Mul(x, p.C)
	r.Add(p.B, &r)
	r.Mul(x, &r)
	return r.Add(p.A, &r)
}

func ScalarExpVartime(x *ristretto.Scalar, n uint64) *ristretto.Scalar {
	var result, aux ristretto.Scalar
	result.SetOne()
	aux.SetZero()
	aux.Add(&aux, x)

	for n > 0 {
		bit := n & 1
		if bit == 1 {
			result.Mul(&result, &aux)
		}
		n = n >> 1
		aux.Mul(&aux, &aux)
	}
	return &result
}

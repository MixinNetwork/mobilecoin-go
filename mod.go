package api

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/bwesterb/go-ristretto"
	"github.com/dchest/blake2b"
)

func keyImageFromPrivate(private *ristretto.Scalar) *ristretto.Point {
	var p ristretto.Point
	p.ScalarMultBase(private)

	hp := hashToPoint(&p)
	var point ristretto.Point
	return point.ScalarMult(hp, private)
}

func hashToPoint(public *ristretto.Point) *ristretto.Point {
	hash := blake2b.New512()
	hash.Write([]byte(HASH_TO_POINT_DOMAIN_TAG))
	hash.Write(public.Bytes())
	var key [64]byte
	copy(key[:], hash.Sum(nil))

	var r1Bytes, r2Bytes [32]byte
	copy(r1Bytes[:], key[:32])
	copy(r2Bytes[:], key[32:])
	var r, r1, r2 ristretto.Point
	return r.Add(r1.SetElligator(&r1Bytes), r2.SetElligator(&r2Bytes))
}

func hashToScalar(r *ristretto.Point, a *ristretto.Scalar) *ristretto.Scalar {
	var point ristretto.Point
	var hs ristretto.Scalar
	hash := blake2b.New512()
	hash.Write([]byte(HASH_TO_SCALAR_DOMAIN_TAG))
	hash.Write(point.ScalarMult(r, a).Bytes())
	var key [64]byte
	copy(key[:], hash.Sum(nil))

	return hs.SetReduced(&key)
}

func uint64ToScalar(i uint64) *ristretto.Scalar {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:], i)
	var s ristretto.Scalar
	return s.SetBytes(&buf)
}

func hexToScalar(h string) *ristretto.Scalar {
	buf, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	var buf32 [32]byte
	copy(buf32[:], buf)
	var s ristretto.Scalar
	return s.SetBytes(&buf32)
}

func hexToPoint(h string) *ristretto.Point {
	buf, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	var buf32 [32]byte
	copy(buf32[:], buf)
	var s ristretto.Point
	s.SetBytes(&buf32)
	return &s
}

func multiscalarMul(scalars []*ristretto.Scalar, points []*ristretto.Point) *ristretto.Point {
	var p ristretto.Point
	p.SetZero()
	for i := range scalars {
		var t ristretto.Point
		t.ScalarMult(points[i], scalars[i])
		p.Add(&p, &t)
	}
	return &p
}

func fromBytesModOrderWide(data []byte) *ristretto.Scalar {
	var data64 [64]byte
	copy(data64[:], data)
	var hs ristretto.Scalar
	return hs.SetReduced(&data64)
}

func resizeUint64ToPow2(vec []uint64) []uint64 {
	l := nextPowerOfTwo(len(vec))
	for i := len(vec); i < l; i++ {
		vec = append(vec, vec[i-1])
	}
	return vec
}

func resizeScalarToPow2(vec []*ristretto.Scalar) []*ristretto.Scalar {
	l := nextPowerOfTwo(len(vec))
	for i := len(vec); i < l; i++ {
		var zero ristretto.Scalar
		vec = append(vec, zero.Add(&zero, vec[i-1]))
	}
	return vec
}

func nextPowerOfTwo(v int) int {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

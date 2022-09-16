package api

import (
	"encoding/binary"

	"github.com/bwesterb/go-ristretto"
	"golang.org/x/crypto/sha3"
)

type PedersenGens struct {
	B         *ristretto.Point
	BBlinding *ristretto.Point
}

func NewPedersenGens() *PedersenGens {
	var base ristretto.Point
	base.SetBase()

	return &PedersenGens{
		B:         hashToPoint(&base),
		BBlinding: &base,
	}
}

func DefaultPedersenGens() *PedersenGens {
	var base ristretto.Point
	base.SetBase()

	h := sha3.New512()
	h.Write(base.Bytes())

	return &PedersenGens{
		B:         &base,
		BBlinding: pointFromUniformBytes(h.Sum(nil)),
	}
}

// CommitPedersenGens includes multiscalar_mul
func (pg *PedersenGens) Commit(value, blinding *ristretto.Scalar) *ristretto.Point {
	return multiscalarMul([]*ristretto.Scalar{value, blinding}, []*ristretto.Point{pg.B, pg.BBlinding})
}

type BulletproofGens struct {
	GensCapacity  int64
	PartyCapacity int64
	GVec          [][]*ristretto.Point
	HVec          [][]*ristretto.Point
}

func NewBulletproofGens(gensCapacity, partyCapacity int64) *BulletproofGens {
	b := &BulletproofGens{
		GensCapacity:  0,
		PartyCapacity: partyCapacity,
		GVec:          make([][]*ristretto.Point, partyCapacity),
		HVec:          make([][]*ristretto.Point, partyCapacity),
	}
	b.IncreaseCapacity(gensCapacity)
	return b
}

func (b *BulletproofGens) IncreaseCapacity(capacity int64) {
	if b.GensCapacity >= capacity {
		return
	}
	for i := 0; i < int(b.PartyCapacity); i++ {
		var byte32 [4]byte
		binary.LittleEndian.PutUint32(byte32[:], uint32(i))
		label := []byte("G")
		label = append(label, byte32[:]...)
		chainG := NewGeneratorsChain(label)
		chainG.FastForward(b.GensCapacity)

		genPoints := make([]*ristretto.Point, capacity-b.GensCapacity)
		for j := 0; j < int(capacity-b.GensCapacity); j++ {
			genPoints[j] = chainG.Next()
		}
		b.GVec[i] = genPoints

		label[0] = []byte("H")[0]
		chainP := NewGeneratorsChain(label)
		chainP.FastForward(b.GensCapacity)
		partyPoints := make([]*ristretto.Point, capacity-b.GensCapacity)
		for j := 0; j < int(capacity-b.GensCapacity); j++ {
			partyPoints[j] = chainP.Next()
		}
		b.HVec[i] = partyPoints
	}
	b.GensCapacity = capacity
}

func (b *BulletproofGens) G(n, m int64) *AggregatedGensIter {
	return &AggregatedGensIter{
		N:        n,
		M:        m,
		Array:    b.GVec,
		PartyIdX: 0,
		GenIdX:   0,
	}
}

func (b *BulletproofGens) H(n, m int64) *AggregatedGensIter {
	return &AggregatedGensIter{
		N:        n,
		M:        m,
		Array:    b.HVec,
		PartyIdX: 0,
		GenIdX:   0,
	}
}

type AggregatedGensIter struct {
	Array    [][]*ristretto.Point
	N, M     int64
	PartyIdX int64
	GenIdX   int64
}

func (a *AggregatedGensIter) Next() *ristretto.Point {
	if a.GenIdX >= a.N {
		a.GenIdX = 0
		a.PartyIdX += 1
	}
	if a.PartyIdX >= a.M {
		return nil
	}
	cur_gen := a.GenIdX
	a.GenIdX += 1
	return a.Array[a.PartyIdX][cur_gen]
}

type GeneratorsChain struct {
	sha3.ShakeHash
}

func NewGeneratorsChain(label []byte) *GeneratorsChain {
	h := sha3.NewShake256()
	h.Write([]byte("GeneratorsChain"))
	h.Write(label)
	return &GeneratorsChain{h}
}

func (c *GeneratorsChain) FastForward(n int64) {
	for i := 0; i < int(n); i++ {
		var data [64]byte
		c.Read(data[:])
	}
}

func (c *GeneratorsChain) Next() *ristretto.Point {
	var data [64]byte
	c.Read(data[:])
	return pointFromUniformBytes(data[:])
}

func pointFromUniformBytes(key []byte) *ristretto.Point {
	var r1Bytes, r2Bytes [32]byte
	copy(r1Bytes[:], key[:32])
	copy(r2Bytes[:], key[32:])
	var r, r1, r2 ristretto.Point
	return r.Add(r1.SetElligator(&r1Bytes), r2.SetElligator(&r2Bytes))
}

type BulletproofGensShare struct {
	Gens  *BulletproofGens
	Share int
}

func (g *BulletproofGens) Share(j int) *BulletproofGensShare {
	return &BulletproofGensShare{
		Gens:  g,
		Share: j,
	}
}

func (g *BulletproofGensShare) G(n int64) []*ristretto.Point {
	return g.Gens.GVec[g.Share][:n]
}

func (g *BulletproofGensShare) H(n int64) []*ristretto.Point {
	return g.Gens.HVec[g.Share][:n]
}

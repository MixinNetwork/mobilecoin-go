package api

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testGenerators(t *testing.T) {
	assert := assert.New(t)

	bg := NewBulletproofGens(64, 64)
	assert.Equal(64, bg.GensCapacity)
	assert.Equal(64, bg.PartyCapacity)
	assert.Len(bg.GVec, 64)
	assert.Len(bg.HVec, 64)

	pg := NewPedersenGens()
	assert.Equal("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76", hex.EncodeToString(pg.B.Bytes()))
	assert.Equal("8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134", hex.EncodeToString(pg.BBlinding.Bytes()))
}

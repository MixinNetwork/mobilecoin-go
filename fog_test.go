package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFog(t *testing.T) {
	assert := assert.New(t)
	hint, err := fakeOnetimeHint()
	assert.Equal(err, nil)
	assert.Equal(EncryptedFogHintSize, len(hint))
}

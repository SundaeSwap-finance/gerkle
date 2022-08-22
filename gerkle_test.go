package gerkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/tj/assert"
	"golang.org/x/crypto/blake2b"
)

type Str string

func (s Str) String() string { return string(s) }

func Test(t *testing.T) {
	strs := []fmt.Stringer{
		Str("A"),
		Str("B"),
		Str("C"),
		Str("D"),
		Str("E"),
		Str("F"),
		Str("G"),
	}

	hash, err := blake2b.New256(nil)
	assert.Nil(t, err)

	mt, err := Build(hash, false, 0x31, strs)
	assert.Nil(t, err)
	mt.Print(0)
	assert.Equal(t, "5483ad15710ff90055105b6915221db1887242f0d71f0b0e5744ddd7b672cc34", hex.EncodeToString(mt.Hash))
	proof, err := mt.FindProofFor(Str("D"))
	assert.Nil(t, err)
	assert.Len(t, proof, 5)

	err = mt.CheckProof(proof)
	assert.Nil(t, err)

	proof[1].Hash[2] += 1
	err = mt.CheckProof(proof)
	assert.NotNil(t, err)
}

func Test_Empty(t *testing.T) {
	strs := []fmt.Stringer{}

	hash, err := blake2b.New256(nil)
	assert.Nil(t, err)

	tree, err := Build(hash, false, 0x31, strs)
	assert.Nil(t, err)
	assert.Equal(t, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", hex.EncodeToString(tree.Hash))
}

func Test_SHA256HexColon(t *testing.T) {
	strs := []fmt.Stringer{
		Str("A"),
		Str("B"),
		Str("C"),
		Str("D"),
		Str("E"),
		Str("F"),
		Str("G"),
	}

	hash := sha256.New()

	mt, err := Build(hash, true, ':', strs)
	assert.Nil(t, err)
	mt.Print(0)
	assert.Equal(t, "33dc5cfadad32f7315dfe0d6bf74329dbb85b458a81c3e645e8d1c4bf12b1fb4", hex.EncodeToString(mt.Hash))
	proof, err := mt.FindProofFor(Str("D"))
	assert.Nil(t, err)
	assert.Len(t, proof, 5)

	err = mt.CheckProof(proof)
	assert.Nil(t, err)

	proof[1].Hash[2] += 1

	err = mt.CheckProof(proof)
	assert.NotNil(t, err)
}

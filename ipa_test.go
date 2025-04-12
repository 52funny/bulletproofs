package bulletproofs_test

import (
	"testing"

	"github.com/52funny/bulletproofs"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestIPA(t *testing.T) {
	n := 128
	pp := bulletproofs.NewPublicParameters(n)
	aVec := make([]fr.Element, n)
	bVec := make([]fr.Element, n)

	for i := range n {
		aVec[i].SetRandom()
		bVec[i].SetRandom()
	}

	L, R, a, b := pp.IPAProof(aVec, bVec)

	res := pp.IPAVerify(L, R, aVec, bVec, a, b)
	assert.Equal(t, true, res)
}

package bulletproofs_test

import (
	"testing"

	"github.com/52funny/bulletproofs"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestIPA(t *testing.T) {
	n := 128
	aVec, bVec := make([]fr.Element, n), make([]fr.Element, n)
	for i := range n {
		aVec[i].SetRandom()
		bVec[i].SetRandom()
	}
	pp := bulletproofs.NewIPAParameters(n)
	P := pp.IPAPerdersonCommitment(pp.G, pp.H, aVec, bVec)
	L, R, a, b := pp.IPAProof(pp.G, pp.H, aVec, bVec)
	res := pp.IPAVerify(pp.G, pp.H, L, R, P, a, b)
	assert.Equal(t, true, res)
}

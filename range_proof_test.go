package bulletproofs

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestNewRangeProver(t *testing.T) {
	n := 256
	dealer := RangeProofDealerSetup(n)
	x := fr.NewElement(3)
	ra := NewRangeProver(dealer, x)
	al := ra.aL
	ar := ra.aR

	one := fr.Element{}
	one.SetOne()
	sub := fr.Element{}
	for i := range n {
		sub.Sub(&al[i], &ar[i])
		assert.Equal(t, true, sub.Equal(&one))
	}

	two := fr.NewElement(2)
	twoVec := newVecofKN(two, n)
	sum := vecInnerProduct(twoVec, al)

	assert.Equal(t, true, sum.Equal(&x))
}

func TestRangeProof(t *testing.T) {
	n := 2
	dealer := RangeProofDealerSetup(n)
	x := fr.Element{}
	x.SetOne()
	// x.SetRandom()
	prover := NewRangeProver(dealer, x)

	proof := prover.Prove()
	verifier := NewRangeVerify(dealer)
	ok := verifier.Verify(proof)
	assert.Equal(t, true, ok)
}

package bulletproofs

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestNewBatchRangeProof(t *testing.T) {
	n, m := 64, 128
	dealer := RangeProofDealerSetup(n * m)
	v := make([]fr.Element, m)
	for i := range m {
		v[i].SetInt64(int64(i))
	}

	prover := NewBatchRangeProof(dealer, n, v...)
	assert.Equal(t, n*m, len(prover.aL))
	assert.Equal(t, n*m, len(prover.aR))

	two := fr.NewElement(2)
	twoN := newVecofKN(two, n)

	for i, expected := range v {
		val := vecInnerProduct(twoN, prover.aL[n*i:n*(i+1)])
		assert.Equal(t, true, expected.Equal(&val))
	}
	one := fr.One()
	for i := range n * m {
		sum := fr.Element{}
		sum.Sub(&prover.aL[i], &prover.aR[i])
		assert.Equal(t, true, one.Equal(&sum))
	}

}

func TestBatchRangeVerify(t *testing.T) {
	n, m := 256, 2
	dealer := RangeProofDealerSetup(n * m)
	v := make([]fr.Element, m)
	for i := range m {
		v[i].SetInt64(int64(i))
	}

	prover := NewBatchRangeProof(dealer, n, v...)
	proof := prover.Prove()

	verify := NewBatchRangeVerify(dealer)
	ok := verify.Verify(proof)
	assert.Equal(t, true, ok)

}

func BenchmarkBatchRangeVerify(b *testing.B) {
	n, m := 256, 2
	dealer := RangeProofDealerSetup(n * m)
	v := make([]fr.Element, m)
	for i := range m {
		v[i].SetInt64(int64(i))
	}

	prover := NewBatchRangeProof(dealer, n, v...)
	b.Run("BatchGenerateProof", func(t *testing.B) {
		b.ResetTimer()
		for i := 0; i < t.N; i++ {
			prover.Prove()
		}
	})

	b.Run("BatchVerifyProof", func(t *testing.B) {
		proof := prover.Prove()
		verify := NewBatchRangeVerify(dealer)
		b.ResetTimer()
		for i := 0; i < t.N; i++ {
			verify.Verify(proof)
		}
	})

}

func TestMakeFr(t *testing.T) {
	x := make([]fr.Element, 10)
	for i := range x {
		assert.True(t, x[i].IsZero())
	}
}

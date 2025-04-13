package bulletproofs_test

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/52funny/bulletproofs"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestNewPublicParameters(t *testing.T) {
	n := 1000
	a, b := make([]fr.Element, n), make([]fr.Element, n)
	for i := range len(a) {
		a[i].SetRandom()
		b[i].SetRandom()
	}
	pp := bulletproofs.NewPublicParameters(n, a, b)
	assert.Equal(t, n, len(pp.G))
}

func BenchmarkMultiExp(bench *testing.B) {
	n := 100
	a, b := make([]fr.Element, n), make([]fr.Element, n)
	pp := bulletproofs.NewPublicParameters(100, a, b)
	frs := make([]fr.Element, n)
	for i := range n {
		frs[i].SetRandom()
	}
	// cfg := ecc.
	cfg := ecc.MultiExpConfig{
		NbTasks: runtime.NumCPU(),
	}
	bench.ResetTimer()
	new(bls12381.G1Affine).MultiExp(pp.G[:n], frs[:n], cfg)
}

func BenchmarkStandardScalarMulti(bench *testing.B) {
	n := 100
	a, b := make([]fr.Element, n), make([]fr.Element, n)
	pp := bulletproofs.NewPublicParameters(100, a, b)
	frs := make([]fr.Element, n)
	for i := range n {
		frs[i].SetRandom()
	}
	bench.ResetTimer()
	sum := bls12381.G1Affine{}
	for i := range n {
		sum.Add(&sum, new(bls12381.G1Affine).ScalarMultiplication(&pp.G[i], frs[i].BigInt(new(big.Int))))
	}
}

package bulletproofs_test

import (
	"math/big"
	"testing"

	"github.com/52funny/bulletproofs"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestNewPublicParameters(t *testing.T) {
	pp := bulletproofs.NewPublicParameters(1000)
	assert.Equal(t, 100, len(pp.G))
}
func TestMultiExp(t *testing.T) {
	n := 100
	pp := bulletproofs.NewPublicParameters(100)
	frs := make([]fr.Element, n)
	for i := range n {
		frs[i].SetRandom()
	}
	// cfg := ecc.
	cfg := ecc.MultiExpConfig{
		NbTasks: 4,
	}
	x, _ := new(bls12381.G1Affine).MultiExp(pp.G[:n], frs[:n], cfg)
	y := new(bls12381.G1Affine).SetInfinity()
	for i := range n {
		y.Add(y, new(bls12381.G1Affine).ScalarMultiplication(&pp.G[i], frs[i].BigInt(new(big.Int))))
	}
	assert.Equal(t, x.String(), y.String())

}

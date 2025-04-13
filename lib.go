package bulletproofs

import (
	"math/big"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const maxGoroutine = 4

type PublicParameters struct {
	G []bls12381.G1Affine
	H []bls12381.G1Affine
	U bls12381.G1Affine
	N int
}

// NewPublicParameters generates public parameters for the ipa protocol.
func NewPublicParameters(n int, a []fr.Element, b []fr.Element) *PublicParameters {
	g := make([]bls12381.G1Affine, 0, n)
	h := make([]bls12381.G1Affine, 0, n)

	wait := new(sync.WaitGroup)
	worker := func(target int) {
		defer wait.Done()
		for range n {
			// generate random number
			r := fr.Element{}
			r.SetRandom()
			random := bls12381.G1Jac{}
			random.ScalarMultiplicationBase(r.BigInt(new(big.Int)))
			switch target {
			case 0:
				g = append(g, *new(bls12381.G1Affine).FromJacobian(&random))
			case 1:
				h = append(h, *new(bls12381.G1Affine).FromJacobian(&random))
			}
		}
	}

	wait.Add(2)
	go worker(0)
	go worker(1)
	wait.Wait()

	r := fr.Element{}
	r.SetRandom()
	u := new(bls12381.G1Affine).FromJacobian(new(bls12381.G1Jac).ScalarMultiplicationBase(r.BigInt(new(big.Int))))

	return &PublicParameters{
		G: g,
		H: h,
		N: n,
		U: *u,
	}
}

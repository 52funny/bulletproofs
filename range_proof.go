package bulletproofs

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type RangeProofDealer struct {
	N   int
	G   bls12381.G1Affine
	H   bls12381.G1Affine
	IPA *IPAParameters
}

func RangeProofDealerSetup(n int) *RangeProofDealer {
	g, h := bls12381.G1Affine{}, bls12381.G1Affine{}

	// random number
	r := fr.Element{}
	r.SetRandom()

	// g and h
	g.ScalarMultiplicationBase(r.BigInt(new(big.Int)))
	r.SetRandom()
	h.ScalarMultiplicationBase(r.BigInt(new(big.Int)))

	ipa := NewIPAParameters(n)

	return &RangeProofDealer{
		N:   n,
		G:   g,
		H:   h,
		IPA: ipa,
	}
}

type RangeProver struct {
	gamma  fr.Element
	v      fr.Element
	aL     []fr.Element
	aR     []fr.Element
	dealer *RangeProofDealer
}

func NewRangeProver(dealer *RangeProofDealer, v fr.Element) *RangeProver {
	vBig := v.BigInt(new(big.Int))
	aL := make([]fr.Element, 0, dealer.N)
	aR := make([]fr.Element, 0, dealer.N)
	one := fr.One()
	bMinusOne := fr.Element{}

	gamma := fr.Element{}
	gamma.SetRandom()

	V := bls12381.G1Affine{}
	cfg := ecc.MultiExpConfig{NbTasks: maxGoroutine}
	V.MultiExp([]bls12381.G1Affine{dealer.H, dealer.G}, []fr.Element{gamma, v}, cfg)

	for i := range dealer.N {
		b := fr.Element{}
		b.SetUint64(uint64(vBig.Bit(i)))
		bMinusOne.Sub(&b, &one)
		aL = append(aL, b)
		aR = append(aR, bMinusOne)
	}

	return &RangeProver{
		gamma:  gamma,
		v:      v,
		aL:     aL,
		aR:     aR,
		dealer: dealer,
	}
}

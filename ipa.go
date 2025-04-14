package bulletproofs

import (
	"crypto/sha256"
	"math/big"
	"math/bits"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type IPAParameters struct {
	G []bls12381.G1Affine
	H []bls12381.G1Affine
	U bls12381.G1Affine
	N int
}

// NewIPAParameters generates public parameters for the ipa protocol.
func NewIPAParameters(n int) *IPAParameters {
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

	return &IPAParameters{
		G: g,
		H: h,
		N: n,
		U: *u,
	}
}

func (pp *IPAParameters) IPAProof(a []fr.Element, b []fr.Element) ([]bls12381.G1Affine, []bls12381.G1Affine, fr.Element, fr.Element) {
	if len(a) != len(b) {
		panic("length of a and b must be equal")
	}

	if len(a) <= 0 || len(a)&(len(a)-1) != 0 {
		panic("length of a and b must be power of 2")
	}

	aCopy := make([]fr.Element, len(a))
	bCopy := make([]fr.Element, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	a, b = aCopy, bCopy

	g, h := make([]bls12381.G1Affine, len(pp.G)), make([]bls12381.G1Affine, len(pp.H))
	copy(g, pp.G)
	copy(h, pp.H)

	config := ecc.MultiExpConfig{NbTasks: 8}
	n := len(a)

	LList := make([]bls12381.G1Affine, 0, bits.Len(uint(n)))
	RList := make([]bls12381.G1Affine, 0, bits.Len(uint(n)))

	for n != 1 {
		n = n / 2

		L1, _ := new(bls12381.G1Jac).MultiExp(g[n:2*n], a[0:n], config)
		L2, _ := new(bls12381.G1Jac).MultiExp(h[0:n], b[n:2*n], config)

		LSum := vecInnerProduct(a[0:n], b[n:2*n])

		L3 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&pp.U), LSum.BigInt(new(big.Int)))
		L := new(bls12381.G1Jac).FromAffine(new(bls12381.G1Affine).SetInfinity())
		L.AddAssign(L1)
		L.AddAssign(L2)
		L.AddAssign(L3)

		R1, _ := new(bls12381.G1Jac).MultiExp(g[0:n], a[n:2*n], config)
		R2, _ := new(bls12381.G1Jac).MultiExp(h[n:2*n], b[0:n], config)

		RSum := vecInnerProduct(a[n:2*n], b[0:n])

		R3 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&pp.U), RSum.BigInt(new(big.Int)))
		R := new(bls12381.G1Jac).FromAffine(new(bls12381.G1Affine).SetInfinity())
		R.AddAssign(R1)
		R.AddAssign(R2)
		R.AddAssign(R3)

		// challenge x
		// x = H(L, R)
		xHash := sha256.New()
		LBytes := new(bls12381.G1Affine).FromJacobian(L).Bytes()
		RBytes := new(bls12381.G1Affine).FromJacobian(R).Bytes()
		xHash.Write(LBytes[:])
		xHash.Write(RBytes[:])
		x := fr.Element{}
		x.SetBytes(xHash.Sum(nil))

		// x^-1
		xInv := fr.Element{}
		xInv.Inverse(&x)

		for i := range n {
			n1 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&g[i]), xInv.BigInt(new(big.Int)))
			n2 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&g[n+i]), x.BigInt(new(big.Int)))
			g[i].Add(new(bls12381.G1Affine).FromJacobian(n1), new(bls12381.G1Affine).FromJacobian(n2))

			n3 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&h[i]), x.BigInt(new(big.Int)))
			n4 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&h[n+i]), xInv.BigInt(new(big.Int)))
			h[i].Add(new(bls12381.G1Affine).FromJacobian(n3), new(bls12381.G1Affine).FromJacobian(n4))
		}

		for i := range n {
			// a[i] = x * a[i] + xInv * a[n+i]
			a[i].Mul(&x, &a[i])
			a[n+i].Mul(&xInv, &a[n+i])
			a[i].Add(&a[i], &a[n+i])

			// b[i] = xInv * b[i] + x * b[n+i]
			b[i].Mul(&xInv, &b[i])
			b[n+i].Mul(&x, &b[n+i])
			b[i].Add(&b[i], &b[n+i])
		}
		LList = append(LList, *(new(bls12381.G1Affine).FromJacobian(L)))
		RList = append(RList, *(new(bls12381.G1Affine).FromJacobian(R)))

		g = g[:n]
		h = h[:n]

		// division
		a = a[:n]
		b = b[:n]
	}
	return LList, RList, a[0], b[0]
}

func (pp *IPAParameters) IPAVerify(L []bls12381.G1Affine, R []bls12381.G1Affine, P bls12381.G1Affine, a, b fr.Element) bool {
	if len(L) != len(R) {
		panic("length of L and R must be equal")
	}
	g := make([]bls12381.G1Affine, len(pp.G))
	h := make([]bls12381.G1Affine, len(pp.H))
	copy(g, pp.G)
	copy(h, pp.H)

	// challenge x
	// x = H(L, R)
	xHash := sha256.New()
	x := fr.Element{}
	n := len(pp.G)
	sum := new(bls12381.G1Jac).FromAffine(new(bls12381.G1Affine).SetInfinity())
	sum.AddAssign(new(bls12381.G1Jac).FromAffine(&P))

	cur := 0
	for cur < len(L) {
		xHash.Reset()
		LBytes := L[cur].Bytes()
		RBytes := R[cur].Bytes()
		xHash.Write(LBytes[:])
		xHash.Write(RBytes[:])
		x.SetBytes(xHash.Sum(nil))

		xInv := fr.Element{}
		xInv.Inverse(&x)

		// x ^ 2
		xSquare := fr.Element{}
		xSquare.Square(&x)
		// x^-2
		xInvSquare := fr.Element{}
		xInvSquare.Inverse(&xSquare)

		LSquare := new(bls12381.G1Jac)
		LSquare.ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&L[cur]), xSquare.BigInt(new(big.Int)))
		RSquare := new(bls12381.G1Jac)
		RSquare.ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&R[cur]), xInvSquare.BigInt(new(big.Int)))

		// Sum = Sum \cdot L^{x^2} \cdot R^{x^-2}
		sum.AddAssign(LSquare)
		sum.AddAssign(RSquare)

		n /= 2
		for i := range n {
			n1 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&g[i]), xInv.BigInt(new(big.Int)))
			n2 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&g[n+i]), x.BigInt(new(big.Int)))
			g[i].Add(new(bls12381.G1Affine).FromJacobian(n1), new(bls12381.G1Affine).FromJacobian(n2))

			n3 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&h[i]), x.BigInt(new(big.Int)))
			n4 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&h[n+i]), xInv.BigInt(new(big.Int)))
			h[i].Add(new(bls12381.G1Affine).FromJacobian(n3), new(bls12381.G1Affine).FromJacobian(n4))
		}
		g = g[:n]
		h = h[:n]

		cur += 1
	}

	PPrime := new(bls12381.G1Jac).FromAffine(new(bls12381.G1Affine).SetInfinity())
	p1 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&g[0]), a.BigInt(new(big.Int)))
	p2 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&h[0]), b.BigInt(new(big.Int)))
	p3 := new(bls12381.G1Jac).ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&pp.U), new(fr.Element).Mul(&a, &b).BigInt(new(big.Int)))
	PPrime.AddAssign(p1)
	PPrime.AddAssign(p2)
	PPrime.AddAssign(p3)
	return PPrime.Equal(sum)
}

// Computes the perderson commitment for the given vectors a and b.
func (pp *IPAParameters) IPAPerdersonCommitment(a []fr.Element, b []fr.Element) bls12381.G1Affine {
	if len(a) != len(b) {
		panic("length of a and b must be equal")
	}

	config := ecc.MultiExpConfig{NbTasks: maxGoroutine}
	l1, _ := new(bls12381.G1Affine).MultiExp(pp.G, a, config)
	l2, _ := new(bls12381.G1Affine).MultiExp(pp.H, b, config)
	ipa := vecInnerProduct(a, b)
	l3 := new(bls12381.G1Affine).ScalarMultiplication(&pp.U, ipa.BigInt(new(big.Int)))

	sum := new(bls12381.G1Affine).SetInfinity()
	sum.Add(sum, l1)
	sum.Add(sum, l2)
	sum.Add(sum, l3)
	return *sum
}

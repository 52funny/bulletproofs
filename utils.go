package bulletproofs

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

// vecInnerProduct computes the inner product of two vectors a and b.
// the length of a and b must be equal.
// the result is the sum of a[i] * b[i].
func vecInnerProduct(a []fr.Element, b []fr.Element) fr.Element {
	if len(a) != len(b) {
		panic("length of a and b must be equal")
	}
	sum := fr.NewElement(0)
	for i := range a {
		t := fr.Element{}
		t.Mul(&a[i], &b[i])
		sum.Add(&sum, &t)
	}
	return sum
}

// vecHadamardProduct computes the Hadamard product of two vectors a and b.
// the length of a and b must be equal.
func vecHadamardProduct(a []fr.Element, b []fr.Element) []fr.Element {
	if len(a) != len(b) {
		panic("length of a and b must be equal")
	}
	c := make([]fr.Element, len(a))
	for i := range a {
		c[i].Mul(&a[i], &b[i])
	}
	return c
}

// vecAdd computes the sum of two vectors a and b.
// the length of a and b must be equal.
func vecAdd(a []fr.Element, b []fr.Element) []fr.Element {
	if len(a) != len(b) {
		panic("length of a and b must be equal")
	}
	c := make([]fr.Element, len(a))
	for i := range a {
		c[i].Add(&a[i], &b[i])
	}
	return c
}

// vecSub computes subtraction of two arrays a and b.
// the length of a and b must be equal.
func vecSub(a []fr.Element, b []fr.Element) []fr.Element {
	if len(a) != len(b) {
		panic("length of a and b must be equal")
	}
	c := make([]fr.Element, len(a))
	for i := range a {
		c[i].Sub(&a[i], &b[i])
	}
	return c
}

// vecScalarSub computes the new vector c = a_i - b.
func vecScalarSub(a []fr.Element, b fr.Element) []fr.Element {
	c := make([]fr.Element, len(a))
	for i := range a {
		c[i].Sub(&a[i], &b)
	}
	return c
}

// vecScalarAdd computes the new vector c = a_i + b.
func vecScalarAdd(a []fr.Element, b fr.Element) []fr.Element {
	c := make([]fr.Element, len(a))
	for i := range a {
		c[i].Add(&a[i], &b)
	}
	return c
}

// vecScalarMul computes the product of a vector a and the scalar b.
func vecScalarMul(a []fr.Element, b fr.Element) []fr.Element {
	c := make([]fr.Element, len(a))
	for i := range a {
		c[i].Mul(&a[i], &b)
	}
	return c
}

// newVecofKN computes a new vector of length n where each element is k^i.
func newVecofKN(k fr.Element, n int) []fr.Element {
	c := make([]fr.Element, n)
	prod := fr.NewElement(1)
	for i := range c {
		c[i].Set(&prod)
		prod.Mul(&prod, &k)
	}
	return c
}

// newRandomVec generates a new vector of length n where each element is a random number.
func newRandomVec(n int) []fr.Element {
	c := make([]fr.Element, n)
	for i := range c {
		c[i].SetRandom()
	}
	return c
}

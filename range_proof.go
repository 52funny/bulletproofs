package bulletproofs

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// The RangeProofDealer prepares the parameters for the range proof.
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
	V      bls12381.G1Affine
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
		V:      V,
		aL:     aL,
		aR:     aR,
		dealer: dealer,
	}
}

type RangeProverProof struct {
	A            bls12381.G1Affine
	S            bls12381.G1Affine
	T1           bls12381.G1Affine
	T2           bls12381.G1Affine
	V            bls12381.G1Affine
	TauX         fr.Element
	Mu           fr.Element
	THat         fr.Element
	L            []bls12381.G1Affine
	R            []bls12381.G1Affine
	AVecCompress fr.Element
	BVecCompress fr.Element
}

func (prover *RangeProver) Prove() RangeProverProof {
	A, S := bls12381.G1Affine{}, bls12381.G1Affine{}
	A.SetInfinity()
	S.SetInfinity()
	cfg := ecc.MultiExpConfig{NbTasks: maxGoroutine}

	// α
	alpha := fr.Element{}
	alpha.SetRandom()

	A1, A2, A3 := bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}
	// A1 = h ^ α
	A1.MultiExp([]bls12381.G1Affine{prover.dealer.H}, []fr.Element{alpha}, cfg)
	// A2 = g ^ a_L
	A2.MultiExp(prover.dealer.IPA.G, prover.aL, cfg)
	// A3 = h ^ a_R
	A3.MultiExp(prover.dealer.IPA.H, prover.aR, cfg)
	// A = A1 * A2 * A3
	A.Add(&A1, &A2)
	A.Add(&A, &A3)

	// sL, sR
	sL, sR := newRandomVec(prover.dealer.N), newRandomVec(prover.dealer.N)

	// ρ
	rho := fr.Element{}
	rho.SetRandom()
	S1, S2, S3 := bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}
	S1.MultiExp([]bls12381.G1Affine{prover.dealer.H}, []fr.Element{rho}, cfg)
	S2.MultiExp(prover.dealer.IPA.G, sL, cfg)
	S3.MultiExp(prover.dealer.IPA.H, sR, cfg)
	S.Add(&S1, &S2)
	S.Add(&S, &S3)

	y := fr.Element{}
	yHash := sha256.New()

	VBytes := prover.V.Bytes()
	yHash.Write(VBytes[:])

	nBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nBytes, uint64(prover.dealer.N))
	yHash.Write(nBytes)

	ABytes := A.Bytes()
	yHash.Write(ABytes[:])

	SBytes := S.Bytes()
	yHash.Write(SBytes[:])

	// y = H(V || n || A || S)
	y.SetBytes(yHash.Sum(nil))
	yBytes := y.Bytes()

	z := fr.Element{}
	zHash := sha256.New()

	zHash.Write(ABytes[:])
	zHash.Write(SBytes[:])
	zHash.Write(yBytes[:])

	// z = H(A || S || y)
	z.SetBytes(zHash.Sum(nil))
	zBytes := z.Bytes()

	yN := newVecofKN(y, prover.dealer.N)
	twoN := newVecofKN(fr.NewElement(2), prover.dealer.N)

	// z^2
	zSquare := fr.Element{}
	zSquare.Square(&z)

	t1 := fr.Element{}
	// t11 = <sL, yN ○ (a_R + z)>
	t11 := vecInnerProduct(sL, vecHadamardProduct(yN, vecScalarAdd(prover.aR, z)))
	//t12 = <sL, z^2 * 2^n>
	t12 := vecInnerProduct(sL, vecScalarMul(twoN, zSquare))
	t13 := vecInnerProduct(vecScalarSub(prover.aL, z), vecHadamardProduct(yN, sR))
	// t = t1 * t2 * t3
	t1.Add(&t11, &t12)
	t1.Add(&t1, &t13)

	t2 := vecInnerProduct(sL, vecHadamardProduct(yN, sR))

	T1, T2 := bls12381.G1Affine{}, bls12381.G1Affine{}

	// τ_1, τ_2
	tau1, tau2 := fr.Element{}, fr.Element{}
	tau1.SetRandom()
	tau2.SetRandom()

	T1.MultiExp([]bls12381.G1Affine{prover.dealer.G, prover.dealer.H}, []fr.Element{t1, tau1}, cfg)
	T2.MultiExp([]bls12381.G1Affine{prover.dealer.G, prover.dealer.H}, []fr.Element{t2, tau2}, cfg)

	// assume the x = H(T1 || T2 || y || z)
	x := fr.Element{}
	xHash := sha256.New()
	T1Bytes, T2Bytes := T1.Bytes(), T2.Bytes()

	xHash.Write(T1Bytes[:])
	xHash.Write(T2Bytes[:])
	xHash.Write(yBytes[:])
	xHash.Write(zBytes[:])

	x.SetBytes(xHash.Sum(nil))

	l := vecAdd(vecScalarSub(prover.aL, z), vecScalarMul(sL, x))
	rCenter := vecAdd(vecScalarAdd(prover.aR, z), vecScalarMul(sR, x))
	r := vecAdd(vecHadamardProduct(yN, rCenter), vecScalarMul(twoN, zSquare))

	// x^2
	xSquare := fr.Element{}
	xSquare.Square(&x)

	tHat := vecInnerProduct(l, r)

	taux := fr.Element{}
	taux1, taux2, taux3 := fr.Element{}, fr.Element{}, fr.Element{}
	taux1.Mul(&tau2, &xSquare)
	taux2.Mul(&tau1, &x)
	taux3.Mul(&zSquare, &prover.gamma)

	// taux = taux1 + taux2 + taux3
	taux.Add(&taux1, &taux2)
	taux.Add(&taux, &taux3)

	// μ = ρ * x + α
	mu := fr.Element{}
	mu.Mul(&rho, &x)
	mu.Add(&mu, &alpha)

	yInv := fr.Element{}
	yInv.Inverse(&y)
	yInvN := newVecofKN(yInv, prover.dealer.N)

	hPrime := make([]bls12381.G1Affine, prover.dealer.N)
	for i := range prover.dealer.N {
		hp := new(bls12381.G1Jac)
		hp.ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&prover.dealer.IPA.H[i]), yInvN[i].BigInt(new(big.Int)))
		hPrime[i].FromJacobian(hp)
	}

	L, R, a, b := prover.dealer.IPA.IPAProof(prover.dealer.IPA.G, hPrime, l, r)

	return RangeProverProof{
		A:            A,
		S:            S,
		T1:           T1,
		T2:           T2,
		V:            prover.V,
		TauX:         taux,
		Mu:           mu,
		THat:         tHat,
		L:            L,
		R:            R,
		AVecCompress: a,
		BVecCompress: b,
	}

}

type RangeVerify struct {
	dealer *RangeProofDealer
}

func NewRangeVerify(dealer *RangeProofDealer) *RangeVerify {
	return &RangeVerify{
		dealer: dealer,
	}
}

func (verify *RangeVerify) y(proof *RangeProverProof) fr.Element {
	y := fr.Element{}
	yHash := sha256.New()

	VBytes := proof.V.Bytes()
	yHash.Write(VBytes[:])

	nBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nBytes, uint64(verify.dealer.N))
	yHash.Write(nBytes)

	ABytes := proof.A.Bytes()
	yHash.Write(ABytes[:])

	SBytes := proof.S.Bytes()
	yHash.Write(SBytes[:])

	y.SetBytes(yHash.Sum(nil))
	return y
}

func (verify *RangeVerify) z(proof *RangeProverProof, y *fr.Element) fr.Element {
	z := fr.Element{}
	ABytes := proof.A.Bytes()
	SBytes := proof.S.Bytes()
	yBytes := y.Bytes()

	zHash := sha256.New()
	zHash.Write(ABytes[:])
	zHash.Write(SBytes[:])
	zHash.Write(yBytes[:])

	// z = H(A || S || y)
	z.SetBytes(zHash.Sum(nil))

	return z
}

func (verifier *RangeVerify) x(proof *RangeProverProof, y *fr.Element, z *fr.Element) fr.Element {
	x := fr.Element{}
	xHash := sha256.New()

	T1Bytes := proof.T1.Bytes()
	T2Bytes := proof.T2.Bytes()
	yBytes := y.Bytes()
	zBytes := z.Bytes()

	xHash.Write(T1Bytes[:])
	xHash.Write(T2Bytes[:])
	xHash.Write(yBytes[:])
	xHash.Write(zBytes[:])

	x.SetBytes(xHash.Sum(nil))
	return x
}

func (verifier *RangeVerify) delta(y, z, zSquare *fr.Element, yN []fr.Element, twoN []fr.Element) fr.Element {
	delta := fr.Element{}
	oneN := newVecofKN(fr.One(), verifier.dealer.N)

	// z^3
	zCube := fr.Element{}
	zCube.Mul(z, zSquare)

	zMinusZSquare := fr.Element{}
	zMinusZSquare.Sub(z, zSquare)

	// inner1 = <1, yN>
	// inner2 = <1, 2N>
	inner1, inner2 := vecInnerProduct(oneN, yN), vecInnerProduct(oneN, twoN)

	// left = <1, yN> * (z - z^2)
	left := fr.Element{}
	left.Mul(&zMinusZSquare, &inner1)

	// right = <1, 2N> * z^3
	right := fr.Element{}
	right.Mul(&zCube, &inner2)

	// delta = <1, yN> * (z - z^2) - <1, 2N> * z^3
	delta.Sub(&left, &right)
	return delta
}

func (verifier *RangeVerify) p(proof *RangeProverProof, hPrime []bls12381.G1Affine, yN, twoN []fr.Element, z, zSquare, x *fr.Element) bls12381.G1Affine {
	P := bls12381.G1Affine{}
	P.SetInfinity()
	cfg := ecc.MultiExpConfig{NbTasks: maxGoroutine}

	zNeg := fr.Element{}
	zNeg.Neg(z)

	exp := vecAdd(vecScalarMul(yN, *z), vecScalarMul(twoN, *zSquare))

	// p1 = S^x
	// p2 = g ^ (-z)
	// p3 = h' ^ {z * yN + 2^n * z^2}
	p1, p2, p3 := bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}

	p1.ScalarMultiplication(&proof.S, x.BigInt(new(big.Int)))

	zNegVec := make([]fr.Element, verifier.dealer.N)
	for i := range verifier.dealer.N {
		zNegVec[i].Set(&zNeg)
	}

	p2.MultiExp(verifier.dealer.IPA.G, zNegVec, cfg)

	p3.MultiExp(hPrime, exp, cfg)

	P.Add(&P, &proof.A)
	P.Add(&P, &p1)
	P.Add(&P, &p2)
	P.Add(&P, &p3)

	return P
}

func (verifier *RangeVerify) Verify(proof RangeProverProof) bool {
	cfg := ecc.MultiExpConfig{NbTasks: maxGoroutine}

	y := verifier.y(&proof)
	z := verifier.z(&proof, &y)
	x := verifier.x(&proof, &y, &z)

	yInv := fr.Element{}
	yInv.Inverse(&y)

	zSquare := fr.Element{}
	zSquare.Square(&z)

	xSquare := fr.Element{}
	xSquare.Square(&x)

	yN := newVecofKN(y, verifier.dealer.N)
	twoN := newVecofKN(fr.NewElement(2), verifier.dealer.N)

	// todo: can be optimized
	yInvN := newVecofKN(yInv, verifier.dealer.N)

	hPrime := make([]bls12381.G1Affine, verifier.dealer.N)
	for i := range verifier.dealer.N {
		hp := new(bls12381.G1Jac)
		hp.ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&verifier.dealer.IPA.H[i]), yInvN[i].BigInt(new(big.Int)))
		hPrime[i].FromJacobian(hp)
	}

	// δ(y, z)
	deltaYZ := verifier.delta(&y, &z, &zSquare, yN, twoN)

	left, right := bls12381.G1Affine{}, bls12381.G1Affine{}
	left.MultiExp([]bls12381.G1Affine{verifier.dealer.G, verifier.dealer.H}, []fr.Element{proof.THat, proof.TauX}, cfg)
	right.MultiExp([]bls12381.G1Affine{proof.V, verifier.dealer.G, proof.T1, proof.T2}, []fr.Element{zSquare, deltaYZ, x, xSquare}, cfg)

	ok1 := left.Equal(&right)

	P := verifier.p(&proof, hPrime, yN, twoN, &z, &zSquare, &x)

	hMu := bls12381.G1Affine{}
	hMu.ScalarMultiplication(&verifier.dealer.H, proof.Mu.BigInt(new(big.Int)))
	P.Sub(&P, &hMu)

	// this is the inner product commitment used to determine l and r in the IPA commitment
	// c = THat = <l, r>
	// u^c
	uC := new(bls12381.G1Affine).ScalarMultiplication(&verifier.dealer.IPA.U, proof.THat.BigInt(new(big.Int)))

	P.Add(&P, uC)

	// todo: calculate P
	ok2 := verifier.dealer.IPA.IPAVerify(verifier.dealer.IPA.G, hPrime, proof.L, proof.R, P, proof.AVecCompress, proof.BVecCompress)

	return ok1 && ok2
}

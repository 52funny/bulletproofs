package bulletproofs

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type BatchRangeProver struct {
	N      int
	M      int
	gamma  []fr.Element
	v      []fr.Element
	V      []bls12381.G1Affine
	aL     []fr.Element
	aR     []fr.Element
	dealer *RangeProofDealer
}

type BatchRangeProverProof struct {
	A            bls12381.G1Affine
	S            bls12381.G1Affine
	T1           bls12381.G1Affine
	T2           bls12381.G1Affine
	V            []bls12381.G1Affine
	TauX         fr.Element
	Mu           fr.Element
	THat         fr.Element
	L            []bls12381.G1Affine
	R            []bls12381.G1Affine
	AVecCompress fr.Element
	BVecCompress fr.Element
}

func NewBatchRangeProof(dealer *RangeProofDealer, n int, v ...fr.Element) *BatchRangeProver {
	if len(v) == 0 {
		panic("v must not be empty")
	}
	m := len(v)

	if dealer.N != n*m {
		panic("dealer public parameters length must be n * m")
	}

	gamma := make([]fr.Element, m)
	for i := range m {
		gamma[i].SetRandom()
	}

	aL := make([]fr.Element, n*m)
	aR := make([]fr.Element, n*m)

	V := make([]bls12381.G1Affine, m)
	for i := range m {
		V[i].MultiExp([]bls12381.G1Affine{dealer.G, dealer.H}, []fr.Element{v[i], gamma[i]}, multiExpCfg)
	}

	one := fr.One()
	for j, vVal := range v {
		vBig := vVal.BigInt(new(big.Int))
		bMinusOne := fr.Element{}
		for i := range n {
			b := fr.Element{}
			b.SetUint64(uint64(vBig.Bit(i)))
			bMinusOne.Sub(&b, &one)

			aL[j*n+i].Set(&b)
			aR[j*n+i].Set(&bMinusOne)
		}
	}

	return &BatchRangeProver{
		N:      n,
		M:      m,
		gamma:  gamma,
		v:      v,
		V:      V,
		aL:     aL,
		aR:     aR,
		dealer: dealer,
	}
}
func (prover *BatchRangeProver) computeA(alpha fr.Element) bls12381.G1Affine {
	A := bls12381.G1Affine{}
	A1, A2, A3 := bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}
	// A1 = h ^ α
	A1.MultiExp([]bls12381.G1Affine{prover.dealer.H}, []fr.Element{alpha}, multiExpCfg)
	// A2 = g ^ a_L
	A2.MultiExp(prover.dealer.IPA.G, prover.aL, multiExpCfg)
	// A3 = h ^ a_R
	A3.MultiExp(prover.dealer.IPA.H, prover.aR, multiExpCfg)
	// A = A1 * A2 * A3
	A.Add(&A1, &A2)
	A.Add(&A, &A3)
	return A
}

func (prover *BatchRangeProver) computeS(sL, sR []fr.Element, rho fr.Element) bls12381.G1Affine {
	S := bls12381.G1Affine{}
	S1, S2, S3 := bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}
	S1.MultiExp([]bls12381.G1Affine{prover.dealer.H}, []fr.Element{rho}, multiExpCfg)
	S2.MultiExp(prover.dealer.IPA.G, sL, multiExpCfg)
	S3.MultiExp(prover.dealer.IPA.H, sR, multiExpCfg)
	S.Add(&S1, &S2)
	S.Add(&S, &S3)
	return S
}

func (prover *BatchRangeProver) computeHashy(A, S bls12381.G1Affine) fr.Element {
	y := fr.Element{}
	yHash := sha256.New()

	for _, V := range prover.V {
		VBytes := V.Bytes()
		yHash.Write(VBytes[:])
	}

	nBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nBytes, uint64(prover.dealer.N))
	yHash.Write(nBytes)

	ABytes := A.Bytes()
	yHash.Write(ABytes[:])

	SBytes := S.Bytes()
	yHash.Write(SBytes[:])

	// y = H(V || n || A || S)
	y.SetBytes(yHash.Sum(nil))
	return y
}

func (prover *BatchRangeProver) computeHashz(A, S bls12381.G1Affine, y fr.Element) fr.Element {
	z := fr.Element{}
	zHash := sha256.New()

	ABytes, SBytes, yBytes := A.Bytes(), S.Bytes(), y.Bytes()
	zHash.Write(ABytes[:])
	zHash.Write(SBytes[:])
	zHash.Write(yBytes[:])

	// z = H(A || S || y)
	z.SetBytes(zHash.Sum(nil))
	return z
}

func (prover *BatchRangeProver) computeHashx(T1, T2 bls12381.G1Affine, y, z fr.Element) fr.Element {
	x := fr.Element{}
	xHash := sha256.New()
	T1Bytes, T2Bytes, yBytes, zBytes := T1.Bytes(), T2.Bytes(), y.Bytes(), z.Bytes()

	xHash.Write(T1Bytes[:])
	xHash.Write(T2Bytes[:])
	xHash.Write(yBytes[:])
	xHash.Write(zBytes[:])

	x.SetBytes(xHash.Sum(nil))
	return x
}

func (prover *BatchRangeProver) Prove() BatchRangeProverProof {
	n, m := prover.N, prover.M

	// α
	alpha := fr.Element{}
	alpha.SetRandom()

	A := prover.computeA(alpha)

	// sL, sR
	sL, sR := newRandomVec(n*m), newRandomVec(n*m)

	// ρ
	rho := fr.Element{}
	rho.SetRandom()

	S := prover.computeS(sL, sR, rho)

	// y
	y := prover.computeHashy(A, S)

	// z
	z := prover.computeHashz(A, S, y)

	yNM := newVecofKN(y, n*m)
	twoN := newVecofKN(fr.NewElement(2), n)

	// z^2
	zSquare := fr.Element{}
	zSquare.Square(&z)

	tmp := fr.Element{}
	tmp.Set(&zSquare)

	sumVec := make([]fr.Element, n*m)
	for j := range m {
		paddingVec := newVecWithShift(twoN, n, m, j)
		sumVec = vecAdd(sumVec, vecScalarMul(paddingVec, tmp))
		tmp.Mul(&tmp, &z)
	}

	t1 := fr.Element{}
	// t11 = <sL, yN ○ (a_R + z)>
	t11 := vecInnerProduct(sL, vecHadamardProduct(yNM, vecScalarAdd(prover.aR, z)))
	//t12 = <sL, sumVec>
	t12 := vecInnerProduct(sL, sumVec)
	t13 := vecInnerProduct(vecScalarSub(prover.aL, z), vecHadamardProduct(yNM, sR))
	// t = t1 * t2 * t3
	t1.Add(&t11, &t12)
	t1.Add(&t1, &t13)

	t2 := vecInnerProduct(sL, vecHadamardProduct(yNM, sR))

	T1, T2 := bls12381.G1Affine{}, bls12381.G1Affine{}

	// τ_1, τ_2
	tau1, tau2 := fr.Element{}, fr.Element{}
	tau1.SetRandom()
	tau2.SetRandom()

	T1.MultiExp([]bls12381.G1Affine{prover.dealer.G, prover.dealer.H}, []fr.Element{t1, tau1}, multiExpCfg)
	T2.MultiExp([]bls12381.G1Affine{prover.dealer.G, prover.dealer.H}, []fr.Element{t2, tau2}, multiExpCfg)

	// assume the x = H(T1 || T2 || y || z)
	x := prover.computeHashx(T1, T2, y, z)

	l := vecAdd(vecScalarSub(prover.aL, z), vecScalarMul(sL, x))
	rCenter := vecAdd(vecScalarAdd(prover.aR, z), vecScalarMul(sR, x))
	r := vecAdd(vecHadamardProduct(yNM, rCenter), sumVec)

	// x^2
	xSquare := fr.Element{}
	xSquare.Square(&x)

	tHat := vecInnerProduct(l, r)

	taux := fr.Element{}
	taux1, taux2, taux3 := fr.Element{}, fr.Element{}, fr.Element{}
	taux1.Mul(&tau1, &x)
	taux2.Mul(&tau2, &xSquare)
	taux3.SetZero()

	zTmp := fr.Element{}
	zTmp.Set(&zSquare)

	for _, gamma := range prover.gamma {
		// p = gamma * z^{1 + j}
		p := fr.Element{}
		p.Mul(&zTmp, &gamma)

		taux3.Add(&taux3, &p)
		zTmp.Mul(&zTmp, &z)
	}

	// taux = taux1 + taux2 + taux3
	taux.Add(&taux1, &taux2)
	taux.Add(&taux, &taux3)

	// μ = ρ * x + α
	mu := fr.Element{}
	mu.Mul(&rho, &x)
	mu.Add(&mu, &alpha)

	yInv := fr.Element{}
	yInv.Inverse(&y)
	yInvNM := newVecofKN(yInv, n*m)

	hPrime := make([]bls12381.G1Affine, prover.dealer.N)
	for i := range prover.dealer.N {
		hp := new(bls12381.G1Jac)
		hp.ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&prover.dealer.IPA.H[i]), yInvNM[i].BigInt(new(big.Int)))
		hPrime[i].FromJacobian(hp)
	}

	L, R, a, b := prover.dealer.IPA.IPAProof(prover.dealer.IPA.G, hPrime, l, r)

	return BatchRangeProverProof{
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

type BatchRangeVerify struct {
	dealer *RangeProofDealer
}

func NewBatchRangeVerify(dealer *RangeProofDealer) *BatchRangeVerify {
	return &BatchRangeVerify{
		dealer: dealer,
	}
}

func (verify *BatchRangeVerify) computeHashy(proof *BatchRangeProverProof) fr.Element {
	y := fr.Element{}
	yHash := sha256.New()

	for _, V := range proof.V {
		VBytes := V.Bytes()
		yHash.Write(VBytes[:])
	}

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

func (verify *BatchRangeVerify) computeHashz(proof *BatchRangeProverProof, y *fr.Element) fr.Element {
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

func (verifier *BatchRangeVerify) computeHashx(proof *BatchRangeProverProof, y *fr.Element, z *fr.Element) fr.Element {
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

func (verifier *BatchRangeVerify) computeDelta(n, m int, y, z, zSquare *fr.Element, yNM []fr.Element, twoN []fr.Element) fr.Element {
	delta := fr.Element{}
	oneNM := newVecofKN(fr.One(), n*m)
	oneN := newVecofKN(fr.One(), n)

	// z^3
	zCube := fr.Element{}
	zCube.Mul(z, zSquare)

	zMinusZSquare := fr.Element{}
	zMinusZSquare.Sub(z, zSquare)

	// inner1 = <1, yN>
	// inner2 = <1, 2N>
	inner1, inner2 := vecInnerProduct(oneNM, yNM), vecInnerProduct(oneN, twoN)

	// left = <1, yN> * (z - z^2)
	left := fr.Element{}
	left.Mul(&zMinusZSquare, &inner1)

	zTmp := fr.Element{}
	zTmp.Set(&zCube)

	right := fr.NewElement(0)
	for range m {
		right.Add(&right, new(fr.Element).Mul(&zTmp, &inner2))
		zTmp.Mul(&zTmp, z)
	}

	// delta = <1, yN> * (z - z^2) - <1, 2N> * Σ z^{j+2}
	delta.Sub(&left, &right)
	return delta
}

func (verifier *BatchRangeVerify) computeP(proof *BatchRangeProverProof, hPrime []bls12381.G1Affine, yNM, twoN []fr.Element, z, zSquare, x *fr.Element) bls12381.G1Affine {
	n, m := verifier.dealer.N/len(proof.V), len(proof.V)

	P := bls12381.G1Affine{}
	P.SetInfinity()

	zNeg := fr.Element{}
	zNeg.Neg(z)

	exp := vecScalarMul(yNM, *z)

	// p1 = S^x
	// p2 = g ^ (-z)
	// p3 = h' ^ {z * yNM}
	p1, p2, p3, p4 := bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}

	p1.ScalarMultiplication(&proof.S, x.BigInt(new(big.Int)))

	zNegVec := make([]fr.Element, verifier.dealer.N)
	for i := range verifier.dealer.N {
		zNegVec[i].Set(&zNeg)
	}

	p2.MultiExp(verifier.dealer.IPA.G, zNegVec, multiExpCfg)

	p3.MultiExp(hPrime, exp, multiExpCfg)

	p4Jac := new(bls12381.G1Jac).FromAffine(new(bls12381.G1Affine).SetInfinity())
	t := bls12381.G1Affine{}
	zTmp := fr.Element{}
	zTmp.Set(zSquare)

	for j := range m {
		t.MultiExp(hPrime[j*n:(j+1)*n], vecScalarMul(twoN, zTmp), multiExpCfg)
		p4Jac.AddAssign(new(bls12381.G1Jac).FromAffine(&t))
		zTmp.Mul(&zTmp, z)
	}
	p4.FromJacobian(p4Jac)

	P.Add(&P, &proof.A)
	P.Add(&P, &p1)
	P.Add(&P, &p2)
	P.Add(&P, &p3)
	P.Add(&P, &p4)

	return P
}

func (verifier *BatchRangeVerify) Verify(proof BatchRangeProverProof) bool {
	n, m := verifier.dealer.N/len(proof.V), len(proof.V)

	y := verifier.computeHashy(&proof)
	z := verifier.computeHashz(&proof, &y)
	x := verifier.computeHashx(&proof, &y, &z)

	yInv := fr.Element{}
	yInv.Inverse(&y)

	zSquare := fr.Element{}
	zSquare.Square(&z)

	xSquare := fr.Element{}
	xSquare.Square(&x)

	yNM := newVecofKN(y, n*m)
	twoN := newVecofKN(fr.NewElement(2), n)

	yInvTmp := fr.Element{}
	yInvTmp.SetOne()

	hPrime := make([]bls12381.G1Affine, n*m)
	for i := range verifier.dealer.N {
		hp := new(bls12381.G1Jac)
		hp.ScalarMultiplication(new(bls12381.G1Jac).FromAffine(&verifier.dealer.IPA.H[i]), yInvTmp.BigInt(new(big.Int)))
		hPrime[i].FromJacobian(hp)
		yInvTmp.Mul(&yInvTmp, &yInv)
	}

	// δ(y, z)
	deltaYZ := verifier.computeDelta(n, m, &y, &z, &zSquare, yNM, twoN)

	left, right := bls12381.G1Affine{}, bls12381.G1Affine{}
	left.MultiExp([]bls12381.G1Affine{verifier.dealer.G, verifier.dealer.H}, []fr.Element{proof.THat, proof.TauX}, multiExpCfg)
	right.MultiExp([]bls12381.G1Affine{verifier.dealer.G, proof.T1, proof.T2}, []fr.Element{deltaYZ, x, xSquare}, multiExpCfg)

	zM := newVecofKN(z, m)

	VExp := bls12381.G1Affine{}

	VExp.MultiExp(proof.V, vecScalarMul(zM, zSquare), multiExpCfg)
	right.Add(&right, &VExp)

	ok1 := left.Equal(&right)

	P := verifier.computeP(&proof, hPrime, yNM, twoN, &z, &zSquare, &x)

	hMu := bls12381.G1Affine{}
	hMu.ScalarMultiplication(&verifier.dealer.H, proof.Mu.BigInt(new(big.Int)))
	P.Sub(&P, &hMu)

	// this is the inner product commitment used to determine l and r in the IPA commitment
	// c = THat = <l, r>
	// u^c
	uC := new(bls12381.G1Affine).ScalarMultiplication(&verifier.dealer.IPA.U, proof.THat.BigInt(new(big.Int)))

	P.Add(&P, uC)

	ok2 := verifier.dealer.IPA.IPAFastVerify(verifier.dealer.IPA.G, hPrime, proof.L, proof.R, P, proof.AVecCompress, proof.BVecCompress)

	return ok1 && ok2
}

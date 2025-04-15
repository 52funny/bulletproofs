package bulletproofs

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func Test_newVecWithShift(t *testing.T) {
	n, m := 4, 4
	twoN := newVecofKN(fr.NewElement(2), n)

	for j := range m {
		paddingVec := newVecWithShift(twoN, n, m, j)
		cutVec := paddingVec[j*n : (j+1)*n]

		for i, p := range twoN {
			ok := cutVec[i].Equal(&p)
			assert.True(t, ok)
		}

	}

}

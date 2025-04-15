package bulletproofs

import "github.com/consensys/gnark-crypto/ecc"

const maxGoroutine = 4

var multiExpCfg = ecc.MultiExpConfig{NbTasks: maxGoroutine}

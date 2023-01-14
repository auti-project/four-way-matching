package fwmcircuit

import (
	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

func KeyGen() (*eddsa.PrivateKey, *eddsa.PrivateKey, error) {
	privG, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privH, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privG, privH, nil
}

package fwmcircuit

import (
	"encoding/binary"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func MiMCHashInt64(num int64) *big.Int {
	bigNum := big.NewInt(num)
	f := mimc.NewMiMC()
	f.Write(bigNum.Bytes())
	hashBytes := f.Sum(nil)
	return new(big.Int).SetBytes(hashBytes)
}

func MiMCHashTimestampCounter(timestamp, counter int64) *big.Int {
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))
	f := mimc.NewMiMC()
	f.Write(timestampBytes)
	f.Write(counterBytes)
	hashBytes := f.Sum(nil)
	return new(big.Int).SetBytes(hashBytes)
}

func MiMCHashTimestampCounterToString(timestamp, counter int64) string {
	return MiMCHashTimestampCounter(timestamp, counter).String()
}

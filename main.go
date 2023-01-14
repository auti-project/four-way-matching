// Welcome to the gnark playground!
package main

import (
	"fmt"
	"math/big"
	"time"

	"github.com/auti-project/four-way-matching/fwmcircuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	twistededwards2 "github.com/consensys/gnark/std/algebra/twistededwards"
)

func main() {
	// compiles our circuit into a R1CS
	var circuit fwmcircuit.FWMCircuit
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	handleErr(err)

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	handleErr(err)

	var (
		amount1 int64 = 100
		amount4 int64 = 200
		aux1    int64 = 1
		aux2    int64 = 2
		aux3    int64 = 3
		aux4    int64 = 4
		counter int64 = 10
	)

	timestamp1 := time.Now().UnixNano()
	time.Sleep(200 * time.Millisecond)
	timestamp2 := time.Now().UnixNano()
	time.Sleep(200 * time.Millisecond)
	timestamp3 := time.Now().UnixNano()
	time.Sleep(200 * time.Millisecond)
	timestamp4 := time.Now().UnixNano()

	privateG, privateH, err := fwmcircuit.KeyGen()
	if err != nil {
		panic(err)
	}
	g := &privateG.PublicKey.A // point affine
	h := &privateH.PublicKey.A // point affine
	assignG := twistededwards2.Point{
		X: g.X.String(),
		Y: g.Y.String(),
	}
	assignH := twistededwards2.Point{
		X: h.X.String(),
		Y: h.Y.String(),
	}
	//amountCommit1 := new(twistededwards.PointAffine).ScalarMul(g, big.NewInt(amount1))
	//tmp := new(twistededwards.PointAffine).ScalarMul(
	//	h,
	//	fwmcircuit.MiMCHashTimestampCounter(timestamp1, counter),
	//)
	//amountCommit1.Add(amountCommit1, tmp)
	//assignAmountCommit1 := twistededwards2.Point{
	//	X: amountCommit1.X.String(),
	//	Y: amountCommit1.Y.String(),
	//}
	assignCommitAmount1 := assignCommit(amount1, timestamp1, counter, g, h)
	assignCommitAmount4 := assignCommit(amount4, timestamp4, counter, g, h)
	assignCommitAux1 := assignCommit(aux1, timestamp1, counter, g, h)
	assignCommitAux2 := assignCommit(aux2, timestamp2, counter, g, h)
	assignCommitAux3 := assignCommit(aux3, timestamp3, counter, g, h)
	assignCommitAux4 := assignCommit(aux4, timestamp4, counter, g, h)

	// witness definition
	assignment := fwmcircuit.FWMCircuit{
		G:                 assignG,
		H:                 assignH,
		Counter:           counter,
		Commitment1:       assignCommitAux1,
		Commitment2:       assignCommitAux2,
		Commitment3:       assignCommitAux3,
		Commitment4:       assignCommitAux4,
		AmountCommitment1: assignCommitAmount1,
		AmountCommitment4: assignCommitAmount4,
		Aux1:              aux1,
		Aux2:              aux2,
		Aux3:              aux3,
		Aux4:              aux4,
		Amount1:           amount1,
		Amount4:           200,
		Timestamp1:        timestamp1,
		Timestamp2:        timestamp2,
		Timestamp3:        timestamp3,
		Timestamp4:        timestamp4,
	}
	fmt.Println("test hash", fwmcircuit.MiMCHashTimestampCounter(timestamp1, counter).String())
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	handleErr(err)
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	handleErr(err)
	err = groth16.Verify(proof, vk, publicWitness)
	handleErr(err)

}

func assignCommit(num, timestamp, counter int64, g, h *twistededwards.PointAffine) twistededwards2.Point {
	commit := new(twistededwards.PointAffine).ScalarMul(g, big.NewInt(num))
	tmp := new(twistededwards.PointAffine).ScalarMul(h, fwmcircuit.MiMCHashTimestampCounter(timestamp, counter))
	commit.Add(commit, tmp)
	return twistededwards2.Point{
		X: commit.X.String(),
		Y: commit.Y.String(),
	}
}

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}

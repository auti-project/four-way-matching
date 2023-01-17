// Welcome to the gnark playground!
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/auti-project/four-way-matching/fwmcircuit"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	twistededwards2 "github.com/consensys/gnark/std/algebra/twistededwards"
)

func hashFunc(data []byte) ([]byte, error) {
	mimcHash := mimc.NewMiMC()
	mimcHash.Write(data)
	return mimcHash.Sum(nil), nil
}

func main() {
	var (
		amount1 int64 = 100
		amount4 int64 = 200
		aux1    int64 = 1
		aux2    int64 = 2
		aux3    int64 = 3
		aux4    int64 = 4
		counter int64 = 10
	)

	timestampRangeLeft := time.Now().UnixNano()
	time.Sleep(200 * time.Millisecond)
	timestamp1 := time.Now().UnixNano()
	time.Sleep(200 * time.Millisecond)
	timestamp2 := time.Now().UnixNano()
	time.Sleep(200 * time.Millisecond)
	timestamp3 := time.Now().UnixNano()
	time.Sleep(200 * time.Millisecond)
	timestamp4 := time.Now().UnixNano()
	time.Sleep(200 * time.Millisecond)
	timestampRangeRight := time.Now().UnixNano()

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
	assignCommitAmount1, _ := assignCommit(amount1, timestamp1, counter, g, h)
	assignCommitAmount4, _ := assignCommit(amount4, timestamp4, counter, g, h)
	assignCommitAux1, commitAux1 := assignCommit(aux1, timestamp1, counter, g, h)
	assignCommitAux2, commitAux2 := assignCommit(aux2, timestamp2, counter, g, h)
	assignCommitAux3, commitAux3 := assignCommit(aux3, timestamp3, counter, g, h)
	assignCommitAux4, commitAux4 := assignCommit(aux4, timestamp4, counter, g, h)

	const bufLen = 1000000
	var buf bytes.Buffer
	for i := 0; i < bufLen; i++ {
		if i == 100 {
			buf.Write(commitAux1)
		} else if i == 200 {
			buf.Write(commitAux2)
		} else if i == 300 {
			buf.Write(commitAux3)
		} else if i == 400 {
			buf.Write(commitAux4)
		} else {
			randBuf := make([]byte, 32)
			_, err := rand.Read(randBuf)
			if err != nil {
				panic(err)
			}
			buf.Write(randBuf)
		}
	}
	root1, proof1, numLeaves, err := merkletree.BuildReaderProof(&buf, mimc.NewMiMC(), 32, 100)
	proofHelper1 := merkle.GenerateProofHelper(proof1, 100, numLeaves)
	buf.Reset()
	for i := 0; i < bufLen; i++ {
		if i == 100 {
			buf.Write(commitAux1)
		} else if i == 200 {
			buf.Write(commitAux2)
		} else if i == 300 {
			buf.Write(commitAux3)
		} else if i == 400 {
			buf.Write(commitAux4)
		} else {
			randBuf := make([]byte, 32)
			_, err := rand.Read(randBuf)
			if err != nil {
				panic(err)
			}
			buf.Write(randBuf)
		}
	}
	root2, proof2, numLeaves, err := merkletree.BuildReaderProof(&buf, mimc.NewMiMC(), 32, 200)
	proofHelper2 := merkle.GenerateProofHelper(proof2, 200, numLeaves)
	buf.Reset()
	for i := 0; i < bufLen; i++ {
		if i == 100 {
			buf.Write(commitAux1)
		} else if i == 200 {
			buf.Write(commitAux2)
		} else if i == 300 {
			buf.Write(commitAux3)
		} else if i == 400 {
			buf.Write(commitAux4)
		} else {
			randBuf := make([]byte, 32)
			_, err := rand.Read(randBuf)
			if err != nil {
				panic(err)
			}
			buf.Write(randBuf)
		}
	}
	root3, proof3, numLeaves, err := merkletree.BuildReaderProof(&buf, mimc.NewMiMC(), 32, 300)
	proofHelper3 := merkle.GenerateProofHelper(proof3, 300, numLeaves)
	buf.Reset()
	for i := 0; i < bufLen; i++ {
		if i == 100 {
			buf.Write(commitAux1)
		} else if i == 200 {
			buf.Write(commitAux2)
		} else if i == 300 {
			buf.Write(commitAux3)
		} else if i == 400 {
			buf.Write(commitAux4)
		} else {
			randBuf := make([]byte, 32)
			_, err := rand.Read(randBuf)
			if err != nil {
				panic(err)
			}
			buf.Write(randBuf)
		}
	}
	root4, proof4, numLeaves, err := merkletree.BuildReaderProof(&buf, mimc.NewMiMC(), 32, 400)
	proofHelper4 := merkle.GenerateProofHelper(proof4, 400, numLeaves)

	// compiles our circuit into a R1CS
	var circuit fwmcircuit.FWMCircuit = fwmcircuit.FWMCircuit{
		Path1:   make([]frontend.Variable, len(proof1)),
		Path2:   make([]frontend.Variable, len(proof2)),
		Path3:   make([]frontend.Variable, len(proof3)),
		Path4:   make([]frontend.Variable, len(proof4)),
		Helper1: make([]frontend.Variable, len(proofHelper1)),
		Helper2: make([]frontend.Variable, len(proofHelper2)),
		Helper3: make([]frontend.Variable, len(proofHelper3)),
		Helper4: make([]frontend.Variable, len(proofHelper4)),
	}
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	handleErr(err)

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	handleErr(err)

	// witness definition
	assignment := fwmcircuit.FWMCircuit{
		// statements
		Commitment1:         assignCommitAux1,
		Commitment2:         assignCommitAux2,
		Commitment3:         assignCommitAux3,
		Commitment4:         assignCommitAux4,
		AmountCommitment1:   assignCommitAmount1,
		AmountCommitment4:   assignCommitAmount4,
		TimestampRangeLeft:  timestampRangeLeft,
		TimestampRangeRight: timestampRangeRight,
		Root1:               root1,
		Root2:               root2,
		Root3:               root3,
		Root4:               root4,
		// witnesses
		G:          assignG,
		H:          assignH,
		Counter:    counter,
		Aux1:       aux1,
		Aux2:       aux2,
		Aux3:       aux3,
		Aux4:       aux4,
		Amount1:    amount1,
		Amount4:    amount4,
		Timestamp1: timestamp1,
		Timestamp2: timestamp2,
		Timestamp3: timestamp3,
		Timestamp4: timestamp4,
		Path1:      make([]frontend.Variable, len(proof1)),
		Path2:      make([]frontend.Variable, len(proof2)),
		Path3:      make([]frontend.Variable, len(proof3)),
		Path4:      make([]frontend.Variable, len(proof4)),
		Helper1:    make([]frontend.Variable, len(proofHelper1)),
		Helper2:    make([]frontend.Variable, len(proofHelper2)),
		Helper3:    make([]frontend.Variable, len(proofHelper3)),
		Helper4:    make([]frontend.Variable, len(proofHelper4)),
	}
	for i := range proof1 {
		assignment.Path1[i] = proof1[i]
	}
	for i := range proof2 {
		assignment.Path2[i] = proof2[i]
	}
	for i := range proof3 {
		assignment.Path3[i] = proof3[i]
	}
	for i := range proof4 {
		assignment.Path4[i] = proof4[i]
	}
	for i := range proofHelper1 {
		assignment.Helper1[i] = proofHelper1[i]
	}
	for i := range proofHelper2 {
		assignment.Helper2[i] = proofHelper2[i]
	}
	for i := range proofHelper3 {
		assignment.Helper3[i] = proofHelper3[i]
	}
	for i := range proofHelper4 {
		assignment.Helper4[i] = proofHelper4[i]
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	handleErr(err)
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	handleErr(err)
	err = groth16.Verify(proof, vk, publicWitness)
	handleErr(err)

	// measure the proof size
	proofBytes, err := json.Marshal(proof)
	handleErr(err)
	fmt.Printf("Proof size: %d bytes", len(proofBytes))
}

func assignCommit(num, timestamp, counter int64, g, h *twistededwards.PointAffine) (twistededwards2.Point, []byte) {
	commit := new(twistededwards.PointAffine).ScalarMul(g, big.NewInt(num))
	tmp := new(twistededwards.PointAffine).ScalarMul(h, fwmcircuit.MiMCHashTimestampCounter(timestamp, counter))
	commit.Add(commit, tmp)
	return twistededwards2.Point{
		X: commit.X.String(),
		Y: commit.Y.String(),
	}, commit.Marshal()
}

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}

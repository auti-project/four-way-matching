package fwmcircuit

import (
	twistededwards3 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

// FWMCircuit defines the four-way matching circuit
type FWMCircuit struct {
	// statements
	Commitment1       twistededwards.Point `gnark:",public"`
	Commitment2       twistededwards.Point `gnark:",public"`
	Commitment3       twistededwards.Point `gnark:",public"`
	Commitment4       twistededwards.Point `gnark:",public"`
	AmountCommitment1 twistededwards.Point `gnark:",public"`
	AmountCommitment4 twistededwards.Point `gnark:",public"`
	//MerkleRoot1       frontend.Variable `gnark:",public"`
	//MerkleRoot2       frontend.Variable `gnark:",public"`
	//MerkleRoot3       frontend.Variable `gnark:",public"`
	//MerkleRoot4       frontend.Variable `gnark:",public"`
	//TimeStampRange    frontend.Variable `gnark:",public"`
	// witnessesr
	G          twistededwards.Point `gnark:"g"`
	H          twistededwards.Point `gnark:"h"`
	Counter    frontend.Variable    `gnark:"counter"`
	Aux1       frontend.Variable    `gnark:"aux1"`
	Aux2       frontend.Variable    `gnark:"aux2"`
	Aux3       frontend.Variable    `gnark:"aux3"`
	Aux4       frontend.Variable    `gnark:"aux4"`
	Amount1    frontend.Variable    `gnark:"amount1"`
	Amount4    frontend.Variable    `gnark:"amount4"`
	Timestamp1 frontend.Variable    `gnark:"timestamp1"`
	Timestamp2 frontend.Variable    `gnark:"timestamp2"`
	Timestamp3 frontend.Variable    `gnark:"timestamp3"`
	Timestamp4 frontend.Variable    `gnark:"timestamp4"`
	//MerklePath1 frontend.Variable `gnark:"merkle_path1"`
	//MerklePath2 frontend.Variable `gnark:"merkle_path2"`
	//MerklePath3 frontend.Variable `gnark:"merkle_path3"`
	//MerklePath4 frontend.Variable `gnark:"merkle_path4"`
}

// Define declares the circuit constraints
func (circuit *FWMCircuit) Define(api frontend.API) error {
	// Curve initialization
	curve, err := twistededwards.NewEdCurve(api, twistededwards3.BN254)
	if err != nil {
		return err
	}
	// MiMC Hash initialization
	mimcHash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	// IsLeq(aux1, aux2)
	api.AssertIsLessOrEqual(circuit.Aux1, circuit.Aux2)
	// IsLeq(aux2, aux3)
	api.AssertIsLessOrEqual(circuit.Aux2, circuit.Aux3)
	//IsLeq(aux3, aux4)
	api.AssertIsLessOrEqual(circuit.Aux3, circuit.Aux4)
	// IsLeq(amount1, amount4)
	api.AssertIsLessOrEqual(circuit.Amount1, circuit.Amount4)
	// IsCom(amount1, amount_commitment1)
	circuit.assertCommit(api, &curve, &mimcHash, circuit.Amount1, circuit.Timestamp1, circuit.AmountCommitment1)
	circuit.assertCommit(api, &curve, &mimcHash, circuit.Amount4, circuit.Timestamp4, circuit.AmountCommitment4)
	circuit.assertCommit(api, &curve, &mimcHash, circuit.Aux1, circuit.Timestamp1, circuit.Commitment1)
	circuit.assertCommit(api, &curve, &mimcHash, circuit.Aux2, circuit.Timestamp2, circuit.Commitment2)
	circuit.assertCommit(api, &curve, &mimcHash, circuit.Aux3, circuit.Timestamp3, circuit.Commitment3)
	circuit.assertCommit(api, &curve, &mimcHash, circuit.Aux4, circuit.Timestamp4, circuit.Commitment4)
	return nil
}

func (circuit *FWMCircuit) assertCommit(api frontend.API, curve *twistededwards.Curve, mimcHash *mimc.MiMC,
	num, timestamp frontend.Variable, commit twistededwards.Point) {
	defer mimcHash.Reset()
	preimage := timestamp
	for i := 0; i < 64; i++ {
		preimage = api.Mul(preimage, 2)
	}
	preimage = api.Add(preimage, circuit.Counter)
	mimcHash.Write(preimage)
	timeCounterHash := mimcHash.Sum()
	numCommit := (*curve).ScalarMul(circuit.G, num)
	tmp := (*curve).ScalarMul(circuit.H, timeCounterHash)
	numCommit = (*curve).Add(numCommit, tmp)
	api.AssertIsEqual(commit.X, numCommit.X)
	api.AssertIsEqual(commit.Y, numCommit.Y)
}

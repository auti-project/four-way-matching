// Welcome to the gnark playground!
package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// FWMCircuit defines the four-way matching circuit
type FWMCircuit struct {
	// X       frontend.Variable `gnark:"x"`
	// Y       frontend.Variable `gnark:",public"`
	Amount1 frontend.Variable `gnark:"amount1"`
	Amount4 frontend.Variable `gnark:"amount4"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *FWMCircuit) Define(api frontend.API) error {
	// x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	// api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	// api.AssertIsLessOrEqual(circuit.X, 10)
	api.AssertIsLessOrEqual(circuit.Amount1, circuit.Amount4)
	return nil
}

func main() {
	// compiles our circuit into a R1CS
	var circuit FWMCircuit
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	handleErr(err)

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	handleErr(err)

	// witness definition
	assignment := FWMCircuit{
		Amount1: 3,
		Amount4: 2,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	handleErr(err)
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	handleErr(err)
	err = groth16.Verify(proof, vk, publicWitness)
	handleErr(err)
}

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}

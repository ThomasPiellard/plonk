package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// --------------------------------------------------------------------------

// Circuit defines a simple circuit
// x**3 + x + 5 == y
type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *Circuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	a := api.Add(x3, circuit.X, 5)
	api.Println(a)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func printPoly(p *iop.Polynomial) {
	c := p.Coefficients()
	fmt.Printf("[")
	for i := 0; i < len(c); i++ {
		fmt.Printf("%s, ", c[i].String())
	}
	fmt.Printf("]\n")
}

func printConstraint(l, r, o, ql, qr, qm, qo, qk fr.Element) {
	fmt.Printf(
		"%s*%s+%s*%s+%s*%s*%s+%s*%s+%s\n",
		ql.String(),
		l.String(),
		qr.String(),
		r.String(),
		qm.String(),
		l.String(),
		r.String(),
		qo.String(),
		o.String(),
		qk.String())
}

func printTrace(pt cs.PlonkTrace) {

	size := len(pt.L.Coefficients())
	l := pt.L.Coefficients()
	r := pt.R.Coefficients()
	o := pt.O.Coefficients()
	ql := pt.Ql.Coefficients()
	qr := pt.Qr.Coefficients()
	qm := pt.Qm.Coefficients()
	qo := pt.Qo.Coefficients()
	qk := pt.Qk.Coefficients()

	for i := 0; i < size; i++ {
		printConstraint(l[i], r[i], o[i], ql[i], qr[i], qm[i], qo[i], qk[i])
	}
}

func main() {

	var circuit Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	tccs := ccs.(*cs.SparseR1CS)

	// witness
	var witness Circuit
	witness.X = 3
	witness.Y = 35

	// step 1: populate ql, qr, qm, qo, qk, s1, s2, s3
	validPublicWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	plonkData := cs.SetupWoCommit(tccs, validPublicWitness)

	// step 2: get the solution
	validWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	trace, err := ccs.Solve(validWitness)
	if err != nil {
		fmt.Println(err)
	}

	ttrace := trace.(*cs.SparseR1CSSolution)

	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	plonkData.L = iop.NewPolynomial((*[]fr.Element)(&ttrace.L), lagReg)
	plonkData.R = iop.NewPolynomial((*[]fr.Element)(&ttrace.R), lagReg)
	plonkData.O = iop.NewPolynomial((*[]fr.Element)(&ttrace.O), lagReg)

	printTrace(plonkData)

}

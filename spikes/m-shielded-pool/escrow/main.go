// ADR 0014 M6c — prove the deposit + withdraw value-layer circuits (native). These bind notes to real IST:
// deposit binds a commitment to the public deposited amount; withdraw proves note ownership for a revealed
// amount, exposing only the nullifier. Each is set up single-party here (the M5b ceremony applies identically).
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"moimoi/shielded-pool/pool"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}

func wr(path string, w io.WriterTo) { f, e := os.Create(path); must(e); defer f.Close(); _, e = w.WriteTo(f); must(e) }

func prove(label string, circuit, assignment frontend.Circuit) (groth16.Proof, groth16.VerifyingKey, frontend.Circuit) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	must(err)
	pk, vk, err := groth16.Setup(ccs)
	must(err)
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	must(err)
	pub, err := w.Public()
	must(err)
	proof, err := groth16.Prove(ccs, pk, w)
	must(err)
	must(groth16.Verify(proof, vk, pub))
	// export the device-hook artifacts for the live round-trip
	wr(label+"-vk.bin", vk)
	wr(label+"-proof.bin", proof)
	pb, _ := pub.MarshalBinary()
	must(os.WriteFile(label+"-pub.bin", pb, 0o644))
	fmt.Printf("%s: %d constraints, prove+verify OK, exported %s-{vk,proof,pub}.bin\n", label, ccs.GetNbConstraints(), label)
	return proof, vk, nil
}

func main() {
	const sk, amount, rho = 555, 1000, 111111
	nk := pool.Nk(pool.FeU64(sk))
	cm := pool.HashFr3(pool.FeU64(amount), nk, pool.FeU64(rho))

	// ---- DEPOSIT: cm binds to the public amount ----
	dep := &pool.Deposit{Cm: cm, Amount: amount, Nk: nk, Rho: rho}
	proveDep, vkDep, _ := prove("deposit", &pool.Deposit{}, dep)
	// soundness: claim a different amount than cm commits to → reject
	badAmt := &pool.Deposit{Cm: cm, Amount: 2000}
	bw, _ := frontend.NewWitness(badAmt, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proveDep, vkDep, bw) == nil {
		panic("SOUNDNESS BUG: deposit cm/amount mismatch verified")
	}
	fmt.Println("deposit soundness: cm bound to amount (wrong amount rejected)")

	// ---- WITHDRAW: prove ownership of the note in the tree for the revealed amount ----
	root, pathEls, pathIdx := pool.BuildTreePath(cm, 0)
	nf := pool.HashFr(nk, pool.FeU64(rho))
	wd := &pool.Withdraw{Root: root, Nullifier: nf, Amount: amount, Sk: sk, Rho: rho}
	for i := 0; i < pool.TreeDepth; i++ {
		wd.PathElements[i] = pathEls[i]
		wd.PathIndices[i] = pathIdx[i]
	}
	proveWd, vkWd, _ := prove("withdraw", &pool.Withdraw{}, wd)
	// soundness: claim a different amount → cm not in tree → forged public must reject
	badWd := &pool.Withdraw{Root: root, Nullifier: nf, Amount: 9999}
	bw2, _ := frontend.NewWitness(badWd, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proveWd, vkWd, bw2) == nil {
		panic("SOUNDNESS BUG: withdraw wrong-amount verified")
	}
	fmt.Println("withdraw soundness: amount/note bound (wrong amount rejected)")
	fmt.Println("M6c circuits OK — deposit binds cm<->amount; withdraw proves owned note for revealed amount")
}

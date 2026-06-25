// ADR 0014 M4a/M4b — native demo + WASM entry for the shielded-pool circuit. The circuit + helpers live in
// ./pool so this and the MPC ceremony (./ceremony) prove the IDENTICAL statement (no vk drift). This program
// does a single-party setup (the thing M5b's ceremony replaces) + prove + verify + soundness, and exports the
// device-hook artifacts. Compiled to GOOS=js GOARCH=wasm it runs the same pipeline in the browser (M4b).
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"moimoi/shielded-pool/pool"
)

func main() {
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pool.Transfer{})
	must(err)
	fmt.Printf("compile:  %d constraints in %s\n", ccs.GetNbConstraints(), time.Since(t0).Round(time.Millisecond))

	t0 = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	must(err)
	fmt.Printf("setup:    %s (SINGLE-PARTY — replaced by the MPC ceremony in ./ceremony)\n", time.Since(t0).Round(time.Millisecond))

	w := pool.SampleWitness()
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	must(err)
	pubWitness, err := witness.Public()
	must(err)

	t0 = time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	must(err)
	fmt.Printf("prove:    %s\n", time.Since(t0).Round(time.Millisecond))

	must(groth16.Verify(proof, vk, pubWitness))
	const N = 200
	t0 = time.Now()
	for i := 0; i < N; i++ {
		must(groth16.Verify(proof, vk, pubWitness))
	}
	fmt.Printf("VERIFY:   %s/verify (avg of %d)\n", (time.Since(t0) / N).Round(time.Microsecond), N)

	// soundness: forged nullifier + forged root must FAIL
	bad := &pool.Transfer{Root: w.Root, Nullifier: pool.HashFr(pool.FeU64(999), pool.FeU64(424242)), CmOut0: w.CmOut0, CmOut1: w.CmOut1, Fee: 3}
	badW, _ := frontend.NewWitness(bad, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proof, vk, badW) == nil {
		panic("SOUNDNESS BUG: forged nullifier verified")
	}
	bad2 := &pool.Transfer{Root: pool.HashFr(pool.FeU64(7), pool.FeU64(7)), Nullifier: w.Nullifier, CmOut0: w.CmOut0, CmOut1: w.CmOut1, Fee: 3}
	bad2W, _ := frontend.NewWitness(bad2, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proof, vk, bad2W) == nil {
		panic("SOUNDNESS BUG: forged root verified")
	}
	fmt.Println("soundness: forged nullifier + forged root correctly REJECTED")

	// spend authority (M6a): an attacker with the WRONG sk cannot spend the note — their nk differs, so cmIn
	// is not in the tree, and proving fails (unsatisfiable constraints).
	wrong := pool.SampleWitness()
	wrong.Sk = 12345 // not the owner's key
	wrongW, _ := frontend.NewWitness(wrong, ecc.BN254.ScalarField())
	if _, perr := groth16.Prove(ccs, pk, wrongW); perr == nil {
		panic("SOUNDNESS BUG: spent a note without its spend key")
	}
	fmt.Println("spend authority: wrong sk cannot spend the note (proving fails) — owner-bound")

	writeArtifact("vk.bin", vk)
	writeArtifact("proof.bin", proof)
	pubBytes, err := pubWitness.MarshalBinary()
	must(err)
	must(os.WriteFile("pub.bin", pubBytes, 0o644))
	fmt.Println("exported: vk.bin proof.bin pub.bin")

	// values for the on-chain test: cmIn is the input note to deposit; the rest are the public inputs.
	nk := pool.Nk(pool.FeU64(555))
	cmIn := pool.HashFr3(pool.FeU64(1000), nk, pool.FeU64(111111))
	rootv, _, _ := pool.BuildTreePath(cmIn, 0)
	nf := pool.HashFr(nk, pool.FeU64(111111))
	cmOut0 := pool.HashFr3(pool.FeU64(600), nk, pool.FeU64(222222))
	cmOut1 := pool.HashFr3(pool.FeU64(397), pool.Nk(pool.FeU64(777)), pool.FeU64(333333))
	fmt.Println("CMIN=" + cmIn.String())
	fmt.Println("ROOT=" + rootv.String())
	fmt.Println("NF=" + nf.String())
	fmt.Println("CMOUT0=" + cmOut0.String())
	fmt.Println("CMOUT1=" + cmOut1.String())
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func writeArtifact(path string, w io.WriterTo) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	_, err = w.WriteTo(f)
	must(err)
}

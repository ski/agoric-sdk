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
	bad := &pool.Transfer{Root: w.Root, Nullifier: pool.HashFr(pool.FeU64(999), pool.FeU64(pool.NullifierTag)), CmOut0: w.CmOut0, CmOut1: w.CmOut1, Fee: 3}
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

	writeArtifact("vk.bin", vk)
	writeArtifact("proof.bin", proof)
	pubBytes, err := pubWitness.MarshalBinary()
	must(err)
	must(os.WriteFile("pub.bin", pubBytes, 0o644))
	fmt.Println("exported: vk.bin proof.bin pub.bin")
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

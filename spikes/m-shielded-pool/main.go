// ADR 0014 M4a — the shielded-pool circuit. Upgrades the M1 confidential transfer (spikes/i) from "hidden
// amounts over raw, linkable commitments" to an UNLINKABLE shielded pool (Zcash-Sapling-lite):
//
//   - notes live as commitments cm = MiMC(amount, rho) in a Merkle tree; the spender proves membership of the
//     input note WITHOUT revealing which leaf (so the input is hidden among all notes);
//   - spending reveals a NULLIFIER nf = MiMC(rho, 1) derived from the note's secret rho, NOT the commitment —
//     so an observer cannot link the spend back to any commitment (unlinkability), and a note can be spent once;
//   - value is still CONSERVED (amountIn == out0 + out1 + fee) and outputs are RANGE-checked, in zero knowledge.
//
// Public inputs (declaration order, what the chain sees): [Root, Nullifier, CmOut0, CmOut1, Fee].
// Everything else (amounts, rhos, the Merkle path) stays private on the prover's device.
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

// TreeDepth — 2^8 = 256 notes for the spike. Production widens this (e.g. 32); the circuit shape is identical.
const TreeDepth = 8

// NullifierTag domain-separates nf = MiMC(rho, TAG) from cm = MiMC(amount, rho) so they can never collide.
const NullifierTag = 1

type Transfer struct {
	Root      frontend.Variable `gnark:",public"` // Merkle root of the commitment tree
	Nullifier frontend.Variable `gnark:",public"` // nf of the spent input note (unlinkable to its cm)
	CmOut0    frontend.Variable `gnark:",public"` // new note commitment 0
	CmOut1    frontend.Variable `gnark:",public"` // new note commitment 1
	Fee       frontend.Variable `gnark:",public"` // cleartext protocol fee

	// private witness — never leaves the prover
	AmtIn        frontend.Variable
	RhoIn        frontend.Variable
	PathElements [TreeDepth]frontend.Variable // sibling hashes along the path to the input note
	PathIndices  [TreeDepth]frontend.Variable // 0 = input is left child, 1 = right child, per level

	Amt0, Rho0 frontend.Variable
	Amt1, Rho1 frontend.Variable
}

func (c *Transfer) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hash2 := func(a, b frontend.Variable) frontend.Variable {
		h.Reset()
		h.Write(a, b)
		return h.Sum()
	}

	// 1. the input note commitment opens to (amount, rho)
	cmIn := hash2(c.AmtIn, c.RhoIn)

	// 2. Merkle membership: fold cmIn up the tree to the public Root (proves the note exists, hides which leaf)
	cur := cmIn
	for i := 0; i < TreeDepth; i++ {
		api.AssertIsBoolean(c.PathIndices[i])
		left := api.Select(c.PathIndices[i], c.PathElements[i], cur)
		right := api.Select(c.PathIndices[i], cur, c.PathElements[i])
		cur = hash2(left, right)
	}
	api.AssertIsEqual(cur, c.Root)

	// 3. nullifier derived from the note secret (unlinkable to cmIn; enforces spend-once on-chain)
	api.AssertIsEqual(c.Nullifier, hash2(c.RhoIn, NullifierTag))

	// 4. output notes open to their (amount, rho)
	api.AssertIsEqual(c.CmOut0, hash2(c.Amt0, c.Rho0))
	api.AssertIsEqual(c.CmOut1, hash2(c.Amt1, c.Rho1))

	// 5. conservation — nothing minted or burned
	api.AssertIsEqual(c.AmtIn, api.Add(c.Amt0, c.Amt1, c.Fee))

	// 6. range — outputs are non-negative and fit 64 bits
	api.ToBinary(c.Amt0, 64)
	api.ToBinary(c.Amt1, 64)
	return nil
}

// ---- native MiMC (must match the in-circuit hash so public inputs line up) ----

func feU64(v uint64) fr.Element { var e fr.Element; e.SetUint64(v); return e }

func hashFr(a, b fr.Element) fr.Element {
	h := bn254mimc.NewMiMC()
	ab := a.Bytes()
	bb := b.Bytes()
	h.Write(ab[:])
	h.Write(bb[:])
	var out fr.Element
	out.SetBytes(h.Sum(nil))
	return out
}

func main() {
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Transfer{})
	must(err)
	fmt.Printf("compile:  %d constraints in %s\n", ccs.GetNbConstraints(), time.Since(t0).Round(time.Millisecond))

	t0 = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	must(err)
	fmt.Printf("setup:    %s\n", time.Since(t0).Round(time.Millisecond))

	// a real transfer: 1000 in -> 600 + 397 out + 3 fee, distinct rhos
	const amtIn, out0, out1, fee = 1000, 600, 397, 3
	const rhoIn, rho0, rho1 = 111111, 222222, 333333
	cmIn := hashFr(feU64(amtIn), feU64(rhoIn))
	nf := hashFr(feU64(rhoIn), feU64(NullifierTag))
	cmOut0 := hashFr(feU64(out0), feU64(rho0))
	cmOut1 := hashFr(feU64(out1), feU64(rho1))

	// build a depth-8 tree with cmIn at leaf 0 (rest empty=0); extract the path for leaf 0
	root, pathEls, pathIdx := buildTreePath(cmIn, 0)

	w := &Transfer{
		Root: root, Nullifier: nf, CmOut0: cmOut0, CmOut1: cmOut1, Fee: fee,
		AmtIn: amtIn, RhoIn: rhoIn,
		Amt0: out0, Rho0: rho0, Amt1: out1, Rho1: rho1,
	}
	for i := 0; i < TreeDepth; i++ {
		w.PathElements[i] = pathEls[i]
		w.PathIndices[i] = pathIdx[i]
	}
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

	// soundness: a forged public input (wrong nullifier) must FAIL
	bad := &Transfer{Root: root, Nullifier: hashFr(feU64(999), feU64(NullifierTag)), CmOut0: cmOut0, CmOut1: cmOut1, Fee: fee}
	badW, _ := frontend.NewWitness(bad, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proof, vk, badW) == nil {
		panic("SOUNDNESS BUG: forged nullifier verified")
	}
	// soundness: a forged root (note not in tree) must FAIL
	bad2 := &Transfer{Root: hashFr(feU64(7), feU64(7)), Nullifier: nf, CmOut0: cmOut0, CmOut1: cmOut1, Fee: fee}
	bad2W, _ := frontend.NewWitness(bad2, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proof, vk, bad2W) == nil {
		panic("SOUNDNESS BUG: forged root verified")
	}
	fmt.Println("soundness: forged nullifier + forged root correctly REJECTED")

	// export the device-hook artifacts (vk baked into the chain; proof + public inputs per-tx)
	writeArtifact("vk.bin", vk)
	writeArtifact("proof.bin", proof)
	pubBytes, err := pubWitness.MarshalBinary()
	must(err)
	must(os.WriteFile("pub.bin", pubBytes, 0o644))
	// also print the public inputs as decimals (what the contract's ledger keys on)
	fmt.Println("public inputs [Root, Nullifier, CmOut0, CmOut1, Fee]:")
	fmt.Println("  Root     =", root.String())
	fmt.Println("  Nullifier=", nf.String())
	fmt.Println("  CmOut0   =", cmOut0.String())
	fmt.Println("  CmOut1   =", cmOut1.String())
	fmt.Println("  Fee      = 3")
	fmt.Println("exported: vk.bin proof.bin pub.bin")
}

// buildTreePath builds a depth-TreeDepth tree (empty leaves = 0) with `leaf` at `index`, returning the root,
// the sibling path elements, and the 0/1 index bits along the path.
func buildTreePath(leaf fr.Element, index int) (fr.Element, [TreeDepth]fr.Element, [TreeDepth]int) {
	size := 1 << TreeDepth
	cur := make([]fr.Element, size)
	for i := range cur {
		cur[i] = feU64(0)
	}
	cur[index] = leaf

	var pathEls [TreeDepth]fr.Element
	var pathIdx [TreeDepth]int
	idx := index
	for d := 0; d < TreeDepth; d++ {
		sib := idx ^ 1
		pathEls[d] = cur[sib]
		pathIdx[d] = idx & 1
		next := make([]fr.Element, len(cur)/2)
		for i := range next {
			next[i] = hashFr(cur[2*i], cur[2*i+1])
		}
		cur = next
		idx /= 2
	}
	return cur[0], pathEls, pathIdx
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

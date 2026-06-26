// ADR 0014 M5b — the Groth16 MPC trusted-setup ceremony.
//
// The single-party setup in ../main.go leaves toxic waste (tau) with whoever ran it — they could forge proofs
// and mint hidden value, defeating soundness REGARDLESS of how many validators exist. This replaces it with a
// multi-contribution ceremony (gnark mpcsetup): Phase 1 (powers of tau, circuit-independent) + Phase 2
// (circuit-specific). Each contributor folds in fresh secret randomness over a serialized hand-off; the toxic
// waste is unrecoverable unless EVERY contributor colluded. The resulting vk is what a trustless chain bakes in.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	mpcsetup "github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"moimoi/shielded-pool/pool"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}

// circuitKit returns (emptyCircuit, validWitness, tamperedWitness) for the named circuit. transfer + withdraw are
// the high-stakes ones (forgery mints hidden value / steals from the pool); deposit is lower-stakes (can't mint).
func circuitKit(name string) (frontend.Circuit, frontend.Circuit, frontend.Circuit) {
	amount := uint64(1000)
	sk := pool.FeU64(12345)
	rho := pool.FeU64(67890)
	nk := pool.HashFr(sk, pool.FeU64(pool.NkTag))
	cm := pool.HashFr3(pool.FeU64(amount), nk, rho)
	switch name {
	case "transfer":
		w := pool.SampleWitness()
		bad := &pool.Transfer{Root: w.Root, Nullifier: pool.HashFr(pool.FeU64(999), pool.FeU64(424242)), CmOut0: w.CmOut0, CmOut1: w.CmOut1, Fee: 3}
		return &pool.Transfer{}, w, bad
	case "deposit":
		good := &pool.Deposit{Cm: cm, Amount: amount, Nk: nk, Rho: rho}
		bad := &pool.Deposit{Cm: pool.FeU64(1), Amount: amount, Nk: nk, Rho: rho} // wrong cm
		return &pool.Deposit{}, good, bad
	case "withdraw":
		nf := pool.HashFr(nk, rho)
		root, pathEls, pathIdx := pool.BuildTreePath(cm, 0)
		good := &pool.Withdraw{Root: root, Nullifier: nf, Amount: amount, Sk: sk, Rho: rho}
		bad := &pool.Withdraw{Root: root, Nullifier: pool.FeU64(7), Amount: amount, Sk: sk, Rho: rho} // wrong nf
		for i := 0; i < pool.TreeDepth; i++ {
			good.PathElements[i] = pathEls[i]
			good.PathIndices[i] = pathIdx[i]
			bad.PathElements[i] = pathEls[i]
			bad.PathIndices[i] = pathIdx[i]
		}
		return &pool.Withdraw{}, good, bad
	}
	panic("unknown circuit: " + name + " (transfer|deposit|withdraw)")
}

func main() {
	const nbP1, nbP2 = 3, 3
	name := "transfer"
	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	circuit, goodW, badW := circuitKit(name)

	ccs0, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	must(err)
	ccs := ccs0.(*cs.R1CS)
	domainSize := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))
	fmt.Printf("circuit %q: %d constraints, domain %d; ceremony: %d phase1 + %d phase2 independent contributors\n",
		name, ccs.GetNbConstraints(), domainSize, nbP1, nbP2)

	var bb bytes.Buffer // simulates the serialized hand-off between contributors
	ser := func(v io.WriterTo) []byte { bb.Reset(); _, e := v.WriteTo(&bb); must(e); return slices.Clone(bb.Bytes()) }
	deser := func(v io.ReaderFrom, b []byte) { _, e := v.ReadFrom(bytes.NewReader(b)); must(e) }

	// ---- Phase 1: powers of tau (reusable across circuits) ----
	var p1 mpcsetup.Phase1
	p1.Initialize(domainSize)
	s1 := make([][]byte, nbP1)
	for i := 0; i < nbP1; i++ {
		p1.Contribute() // contributor i folds in fresh secret randomness
		s1[i] = ser(&p1)
		fmt.Printf("  phase1: contributor %d added randomness\n", i+1)
	}
	phase1 := make([]*mpcsetup.Phase1, nbP1)
	for i := range phase1 {
		phase1[i] = new(mpcsetup.Phase1)
		deser(phase1[i], s1[i])
	}
	srs, err := mpcsetup.VerifyPhase1(domainSize, []byte("moimoi phase1 beacon"), phase1...)
	must(err)
	fmt.Println("phase1 verified — contribution chain valid")
	// free Phase-1 working set before the heavier Phase-2 allocates (depth-32 memory headroom: was OOMing).
	s1 = nil
	phase1 = nil
	runtime.GC()
	debug.FreeOSMemory()

	// ---- Phase 2: circuit-specific ----
	var p2 mpcsetup.Phase2
	p2.Initialize(ccs, &srs)
	s2 := make([][]byte, nbP2)
	for i := 0; i < nbP2; i++ {
		p2.Contribute()
		s2[i] = ser(&p2)
		fmt.Printf("  phase2: contributor %d added randomness\n", i+1)
	}
	phase2 := make([]*mpcsetup.Phase2, nbP2)
	for i := range phase2 {
		phase2[i] = new(mpcsetup.Phase2)
		deser(phase2[i], s2[i])
	}
	s2 = nil
	runtime.GC()
	pk, vk, err := mpcsetup.VerifyPhase2(ccs, &srs, []byte("moimoi phase2 beacon"), phase2...)
	must(err)
	fmt.Println("phase2 verified — ceremony pk/vk extracted (toxic waste unrecoverable unless ALL colluded)")

	// ---- prove + verify under the CEREMONY keys ----
	witness, err := frontend.NewWitness(goodW, ecc.BN254.ScalarField())
	must(err)
	pub, err := witness.Public()
	must(err)
	proof, err := groth16.Prove(ccs, pk, witness)
	must(err)
	must(groth16.Verify(proof, vk, pub))
	fmt.Printf("VERIFY[%s]: a proof under the CEREMONY vk verifies — single-party trusted setup eliminated\n", name)

	// soundness still holds under ceremony keys (a tampered public input is rejected)
	badPub, _ := frontend.NewWitness(badW, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proof, vk, badPub) == nil {
		panic("SOUNDNESS BUG: forged public input verified under ceremony vk")
	}
	fmt.Printf("soundness[%s]: forged public input rejected under ceremony vk\n", name)

	// export per-circuit: <name>-ceremony-{vk,proof,pub,pk,ccs}.bin — the realistic flow is ceremony once, ship the pk.
	wr := func(p string, w io.WriterTo) { f, e := os.Create(p); must(e); defer f.Close(); _, e = w.WriteTo(f); must(e) }
	wr(name+"-ceremony-vk.bin", vk)
	wr(name+"-ceremony-proof.bin", proof)
	pb, _ := pub.MarshalBinary()
	must(os.WriteFile(name+"-ceremony-pub.bin", pb, 0o644))
	wr(name+"-ceremony-pk.bin", pk)
	wr(name+"-ceremony-ccs.bin", ccs)
	fmt.Printf("exported: %s-ceremony-{vk,proof,pub,pk,ccs}.bin\n", name)
}

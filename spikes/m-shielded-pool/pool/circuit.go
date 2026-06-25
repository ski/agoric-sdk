// Package pool holds the shared shielded-pool circuit + native helpers, so the native demo (../main.go) and the
// MPC trusted-setup ceremony (../ceremony) compile the IDENTICAL circuit — a single definition, no vk drift.
//
// M6a hardening: notes are OWNER-BOUND with spend authority (Sapling-lite). A spend key sk (passkey-derived)
// yields a nullifier key nk = MiMC(sk, 0). A note commits to its owner: cm = MiMC(amount, nk, rho). The
// nullifier nf = MiMC(nk, rho) needs nk (hence sk) to compute — so only the owner can spend, and the spend is
// unlinkable to the commitment. Outputs are bound to the RECIPIENT's nk. Public shape is unchanged
// [Root, Nullifier, CmOut0, CmOut1, Fee] — the hardening lives entirely in the private witness.
package pool

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const TreeDepth = 32

// domain tags so the MiMC uses (commitment / nullifier / nullifier-key) can never collide.
const (
	NkTag = 0 // nk  = MiMC(sk, NkTag)
)

// Transfer — the M6 hardened shielded-pool statement. Public [Root, Nullifier, CmOut0, CmOut1, Fee].
type Transfer struct {
	Root      frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	CmOut0    frontend.Variable `gnark:",public"`
	CmOut1    frontend.Variable `gnark:",public"`
	Fee       frontend.Variable `gnark:",public"`

	// private witness — never leaves the prover
	Sk           frontend.Variable // spender's secret spend key (passkey-derived)
	AmtIn        frontend.Variable
	RhoIn        frontend.Variable
	PathElements [TreeDepth]frontend.Variable
	PathIndices  [TreeDepth]frontend.Variable

	Amt0, Nk0, Rho0 frontend.Variable // output 0: amount, recipient nullifier key, randomness
	Amt1, Nk1, Rho1 frontend.Variable // output 1
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
	hash3 := func(a, b, cc frontend.Variable) frontend.Variable {
		h.Reset()
		h.Write(a, b, cc)
		return h.Sum()
	}

	// spend authority: derive the spender's nullifier key from the secret spend key
	nk := hash2(c.Sk, NkTag)

	// the input note is OWNER-BOUND: cm = MiMC(amount, nk, rho). A spender with the wrong sk computes a
	// different nk, so cmIn won't match the tree leaf → membership fails → cannot spend another's note.
	cmIn := hash3(c.AmtIn, nk, c.RhoIn)

	// Merkle membership (hides which note)
	cur := cmIn
	for i := 0; i < TreeDepth; i++ {
		api.AssertIsBoolean(c.PathIndices[i])
		left := api.Select(c.PathIndices[i], c.PathElements[i], cur)
		right := api.Select(c.PathIndices[i], cur, c.PathElements[i])
		cur = hash2(left, right)
	}
	api.AssertIsEqual(cur, c.Root)

	// nullifier needs nk (hence sk); unlinkable to cmIn
	api.AssertIsEqual(c.Nullifier, hash2(nk, c.RhoIn))

	// outputs bound to their recipients' nk
	api.AssertIsEqual(c.CmOut0, hash3(c.Amt0, c.Nk0, c.Rho0))
	api.AssertIsEqual(c.CmOut1, hash3(c.Amt1, c.Nk1, c.Rho1))

	// conservation + range
	api.AssertIsEqual(c.AmtIn, api.Add(c.Amt0, c.Amt1, c.Fee))
	api.ToBinary(c.Amt0, 64)
	api.ToBinary(c.Amt1, 64)
	return nil
}

// ---- native MiMC (matches the in-circuit hash) ----

func FeU64(v uint64) fr.Element { var e fr.Element; e.SetUint64(v); return e }

func mimcN(elems ...fr.Element) fr.Element {
	h := bn254mimc.NewMiMC()
	for _, e := range elems {
		b := e.Bytes()
		h.Write(b[:])
	}
	var out fr.Element
	out.SetBytes(h.Sum(nil))
	return out
}

func HashFr(a, b fr.Element) fr.Element     { return mimcN(a, b) }
func HashFr3(a, b, c fr.Element) fr.Element { return mimcN(a, b, c) }

// Nk derives a nullifier key from a spend key (matches the in-circuit nk = MiMC(sk, NkTag)).
func Nk(sk fr.Element) fr.Element { return HashFr(sk, FeU64(NkTag)) }

// BuildTreePath returns the root + Merkle path for a single `leaf` at `index` in an otherwise-empty tree.
// O(depth): every sibling is the empty-subtree hash at that level (zeros[d]), so it works at production depth
// (32) without materializing 2^depth leaves. (The contract maintains the real multi-note tree incrementally;
// a production prover gets its path from that tree state — this is the demo/single-note case.)
func BuildTreePath(leaf fr.Element, index int) (fr.Element, [TreeDepth]fr.Element, [TreeDepth]int) {
	zeros := make([]fr.Element, TreeDepth)
	zeros[0] = FeU64(0)
	for i := 1; i < TreeDepth; i++ {
		zeros[i] = HashFr(zeros[i-1], zeros[i-1])
	}
	var pathEls [TreeDepth]fr.Element
	var pathIdx [TreeDepth]int
	cur := leaf
	for d := 0; d < TreeDepth; d++ {
		bit := (index >> uint(d)) & 1
		pathEls[d] = zeros[d]
		pathIdx[d] = bit
		if bit == 1 {
			cur = HashFr(zeros[d], cur)
		} else {
			cur = HashFr(cur, zeros[d])
		}
	}
	return cur, pathEls, pathIdx
}

// SampleWitness builds the canonical demo transfer: owner sk=555 spends a 1000 note (owner-bound), sending
// 600 to self (nk) + 397 to recipient sk=777 (nkB) + 3 fee. Input note at leaf 0.
func SampleWitness() *Transfer {
	const skIn, skB = 555, 777
	const amtIn, out0, out1, fee = 1000, 600, 397, 3
	const rhoIn, rho0, rho1 = 111111, 222222, 333333

	nk := Nk(FeU64(skIn))
	nkB := Nk(FeU64(skB))
	cmIn := HashFr3(FeU64(amtIn), nk, FeU64(rhoIn))
	nf := HashFr(nk, FeU64(rhoIn))
	cmOut0 := HashFr3(FeU64(out0), nk, FeU64(rho0))   // to self
	cmOut1 := HashFr3(FeU64(out1), nkB, FeU64(rho1))  // to recipient B
	root, pathEls, pathIdx := BuildTreePath(cmIn, 0)

	w := &Transfer{
		Root: root, Nullifier: nf, CmOut0: cmOut0, CmOut1: cmOut1, Fee: fee,
		Sk: skIn, AmtIn: amtIn, RhoIn: rhoIn,
		Amt0: out0, Nk0: nk, Rho0: rho0,
		Amt1: out1, Nk1: nkB, Rho1: rho1,
	}
	for i := 0; i < TreeDepth; i++ {
		w.PathElements[i] = pathEls[i]
		w.PathIndices[i] = pathIdx[i]
	}
	return w
}

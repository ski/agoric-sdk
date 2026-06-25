// Package pool holds the shared shielded-pool circuit + native helpers, so the native demo (../main.go) and the
// MPC trusted-setup ceremony (../ceremony) compile the IDENTICAL circuit — a single definition, no vk drift.
package pool

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// TreeDepth — 2^8 = 256 notes for the spike (production widens this; the circuit shape is identical).
const TreeDepth = 8

// NullifierTag domain-separates nf = MiMC(rho, TAG) from cm = MiMC(amount, rho).
const NullifierTag = 1

// Transfer — the M4 shielded-pool statement. Public [Root, Nullifier, CmOut0, CmOut1, Fee]; rest is private.
type Transfer struct {
	Root      frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	CmOut0    frontend.Variable `gnark:",public"`
	CmOut1    frontend.Variable `gnark:",public"`
	Fee       frontend.Variable `gnark:",public"`

	AmtIn        frontend.Variable
	RhoIn        frontend.Variable
	PathElements [TreeDepth]frontend.Variable
	PathIndices  [TreeDepth]frontend.Variable

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

	cmIn := hash2(c.AmtIn, c.RhoIn)
	cur := cmIn
	for i := 0; i < TreeDepth; i++ {
		api.AssertIsBoolean(c.PathIndices[i])
		left := api.Select(c.PathIndices[i], c.PathElements[i], cur)
		right := api.Select(c.PathIndices[i], cur, c.PathElements[i])
		cur = hash2(left, right)
	}
	api.AssertIsEqual(cur, c.Root)
	api.AssertIsEqual(c.Nullifier, hash2(c.RhoIn, NullifierTag))
	api.AssertIsEqual(c.CmOut0, hash2(c.Amt0, c.Rho0))
	api.AssertIsEqual(c.CmOut1, hash2(c.Amt1, c.Rho1))
	api.AssertIsEqual(c.AmtIn, api.Add(c.Amt0, c.Amt1, c.Fee))
	api.ToBinary(c.Amt0, 64)
	api.ToBinary(c.Amt1, 64)
	return nil
}

// ---- native MiMC (matches the in-circuit hash) ----

func FeU64(v uint64) fr.Element { var e fr.Element; e.SetUint64(v); return e }

func HashFr(a, b fr.Element) fr.Element {
	h := bn254mimc.NewMiMC()
	ab := a.Bytes()
	bb := b.Bytes()
	h.Write(ab[:])
	h.Write(bb[:])
	var out fr.Element
	out.SetBytes(h.Sum(nil))
	return out
}

// BuildTreePath builds a depth-TreeDepth tree (empty leaves = 0) with `leaf` at `index`, returning the root,
// the sibling path elements, and the 0/1 index bits along the path.
func BuildTreePath(leaf fr.Element, index int) (fr.Element, [TreeDepth]fr.Element, [TreeDepth]int) {
	size := 1 << TreeDepth
	cur := make([]fr.Element, size)
	for i := range cur {
		cur[i] = FeU64(0)
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
			next[i] = HashFr(cur[2*i], cur[2*i+1])
		}
		cur = next
		idx /= 2
	}
	return cur[0], pathEls, pathIdx
}

// SampleWitness builds the canonical demo transfer (1000 -> 600 + 397 + 3 fee, input note at leaf 0).
// Returns the assignment for proving. Used by both the demo and the ceremony so they prove the same statement.
func SampleWitness() *Transfer {
	const amtIn, out0, out1, fee = 1000, 600, 397, 3
	const rhoIn, rho0, rho1 = 111111, 222222, 333333
	cmIn := HashFr(FeU64(amtIn), FeU64(rhoIn))
	nf := HashFr(FeU64(rhoIn), FeU64(NullifierTag))
	cmOut0 := HashFr(FeU64(out0), FeU64(rho0))
	cmOut1 := HashFr(FeU64(out1), FeU64(rho1))
	root, pathEls, pathIdx := BuildTreePath(cmIn, 0)

	w := &Transfer{
		Root: root, Nullifier: nf, CmOut0: cmOut0, CmOut1: cmOut1, Fee: fee,
		AmtIn: amtIn, RhoIn: rhoIn, Amt0: out0, Rho0: rho0, Amt1: out1, Rho1: rho1,
	}
	for i := 0; i < TreeDepth; i++ {
		w.PathElements[i] = pathEls[i]
		w.PathIndices[i] = pathIdx[i]
	}
	return w
}

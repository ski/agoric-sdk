package pool

import "github.com/consensys/gnark/frontend"
import "github.com/consensys/gnark/std/hash/mimc"

// ADR 0014 M6c — the value-layer circuits that bind notes to real escrowed IST.
//
// Deposit (public amount): proves a commitment opens to the PUBLIC deposited amount under a hidden owner key +
// randomness, so the contract can escrow exactly `Amount` IST and insert `Cm` knowing they match — without
// learning the owner key. (Deposit is public anyway; privacy begins with later transfers.)
//
// Withdraw: proves ownership of a note in the tree for a REVEALED amount, exposing only the nullifier — so the
// contract pays out exactly `Amount` IST and burns the note, unlinkable to its commitment.

// Deposit: public [Cm, Amount]; private [Nk, Rho].  cm = MiMC(amount, nk, rho).
type Deposit struct {
	Cm     frontend.Variable `gnark:",public"`
	Amount frontend.Variable `gnark:",public"`

	Nk  frontend.Variable
	Rho frontend.Variable
}

func (c *Deposit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.Amount, c.Nk, c.Rho)
	api.AssertIsEqual(c.Cm, h.Sum())
	api.ToBinary(c.Amount, 64) // range
	return nil
}

// Withdraw: public [Root, Nullifier, Amount]; private [Sk, Rho, path].
// Proves: nk=MiMC(sk,0); cm=MiMC(amount,nk,rho); cm in tree → Root; nf=MiMC(nk,rho). Amount is revealed.
type Withdraw struct {
	Root      frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	Amount    frontend.Variable `gnark:",public"`

	Sk           frontend.Variable
	Rho          frontend.Variable
	PathElements [TreeDepth]frontend.Variable
	PathIndices  [TreeDepth]frontend.Variable
}

func (c *Withdraw) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hash2 := func(a, b frontend.Variable) frontend.Variable { h.Reset(); h.Write(a, b); return h.Sum() }
	hash3 := func(a, b, cc frontend.Variable) frontend.Variable { h.Reset(); h.Write(a, b, cc); return h.Sum() }

	nk := hash2(c.Sk, NkTag)
	cm := hash3(c.Amount, nk, c.Rho)
	cur := cm
	for i := 0; i < TreeDepth; i++ {
		api.AssertIsBoolean(c.PathIndices[i])
		left := api.Select(c.PathIndices[i], c.PathElements[i], cur)
		right := api.Select(c.PathIndices[i], cur, c.PathElements[i])
		cur = hash2(left, right)
	}
	api.AssertIsEqual(cur, c.Root)
	api.AssertIsEqual(c.Nullifier, hash2(nk, c.Rho))
	api.ToBinary(c.Amount, 64)
	return nil
}

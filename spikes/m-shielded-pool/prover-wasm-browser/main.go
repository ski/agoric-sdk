//go:build js && wasm

// ADR 0014 M7d — the BROWSER shielded prover. Unlike the node prover (prover-wasm, which os.ReadFile's the pk),
// the browser has no filesystem, so this exposes a syscall/js function the client calls with the ceremony pk +
// ccs (fetched as assets) and the transfer inputs; it builds the witness from passkey-derived secrets and
// returns the proof + public inputs (base64). Secrets never leave the wasm.
//
//   globalThis.proveShielded(pkB64, ccsB64, inputsJson) -> { proof, pub } | { error }
//
// inputs JSON (all decimal strings unless noted): { sk, amtIn, rhoIn, leafIndex(number), amt0, nk0, rho0, amt1, nk1, rho1 }
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"syscall/js"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"

	"moimoi/shielded-pool/pool"
)

type inputs struct {
	Sk        string `json:"sk"`
	AmtIn     uint64 `json:"amtIn"`
	RhoIn     string `json:"rhoIn"`
	LeafIndex int    `json:"leafIndex"`
	Amt0      uint64 `json:"amt0"`
	Nk0       string `json:"nk0"`
	Rho0      string `json:"rho0"`
	Amt1      uint64 `json:"amt1"`
	Nk1       string `json:"nk1"`
	Rho1      string `json:"rho1"`
}

func feDec(s string) fr.Element {
	var e fr.Element
	n, _ := new(big.Int).SetString(s, 10)
	if n != nil {
		e.SetBigInt(n)
	}
	return e
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func errObj(msg string) any { return map[string]any{"error": msg} }

// proveShielded(pkB64, ccsB64, inputsJson) -> { proof, pub } (base64) or { error }
func proveShielded(_ js.Value, args []js.Value) any {
	defer func() { recover() }() // never crash the page; errors surface as {error}
	if len(args) < 3 {
		return errObj("proveShielded(pkB64, ccsB64, inputsJson)")
	}
	pkBytes, err := base64.StdEncoding.DecodeString(args[0].String())
	if err != nil {
		return errObj("bad pk base64")
	}
	ccsBytes, err := base64.StdEncoding.DecodeString(args[1].String())
	if err != nil {
		return errObj("bad ccs base64")
	}
	var in inputs
	if err := json.Unmarshal([]byte(args[2].String()), &in); err != nil {
		return errObj("bad inputs json: " + err.Error())
	}

	ccs := groth16.NewCS(ecc.BN254).(*cs.R1CS)
	if _, err := ccs.ReadFrom(bytes.NewReader(ccsBytes)); err != nil {
		return errObj("ccs read: " + err.Error())
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
		return errObj("pk read: " + err.Error())
	}

	// build the witness from the (passkey-derived) secrets — never leaves the wasm
	sk := feDec(in.Sk)
	rhoIn := feDec(in.RhoIn)
	nk := pool.HashFr(sk, pool.FeU64(pool.NkTag))
	cmIn := pool.HashFr3(pool.FeU64(in.AmtIn), nk, rhoIn)
	nf := pool.HashFr(nk, rhoIn)
	cmOut0 := pool.HashFr3(pool.FeU64(in.Amt0), feDec(in.Nk0), feDec(in.Rho0))
	cmOut1 := pool.HashFr3(pool.FeU64(in.Amt1), feDec(in.Nk1), feDec(in.Rho1))
	root, pathEls, pathIdx := pool.BuildTreePath(cmIn, in.LeafIndex)

	w := &pool.Transfer{
		Root: root, Nullifier: nf, CmOut0: cmOut0, CmOut1: cmOut1, Fee: in.AmtIn - in.Amt0 - in.Amt1,
		Sk: sk, AmtIn: in.AmtIn, RhoIn: rhoIn,
		Amt0: in.Amt0, Nk0: feDec(in.Nk0), Rho0: feDec(in.Rho0),
		Amt1: in.Amt1, Nk1: feDec(in.Nk1), Rho1: feDec(in.Rho1),
	}
	for i := 0; i < pool.TreeDepth; i++ {
		w.PathElements[i] = pathEls[i]
		w.PathIndices[i] = pathIdx[i]
	}

	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		return errObj("witness: " + err.Error())
	}
	pubW, err := witness.Public()
	if err != nil {
		return errObj("public: " + err.Error())
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return errObj("prove: " + err.Error())
	}

	var pb bytes.Buffer
	if _, err := proof.WriteTo(&pb); err != nil {
		return errObj("proof serialize: " + err.Error())
	}
	pubBytes, err := pubW.MarshalBinary()
	if err != nil {
		return errObj("pub serialize: " + err.Error())
	}
	return map[string]any{"proof": b64(pb.Bytes()), "pub": b64(pubBytes)}
}

type depositInputs struct {
	Cm     string `json:"cm"`
	Amount uint64 `json:"amount"`
	Nk     string `json:"nk"`
	Rho    string `json:"rho"`
}

// proveShieldedDeposit(pkB64, ccsB64, inputsJson) -> {proof, pub} — binds a commitment to the public amount.
func proveShieldedDeposit(_ js.Value, args []js.Value) any {
	defer func() { recover() }()
	if len(args) < 3 {
		return errObj("proveShieldedDeposit(pkB64, ccsB64, inputsJson)")
	}
	ccs, pk, e := loadKeys(args[0].String(), args[1].String())
	if e != "" {
		return errObj(e)
	}
	var in depositInputs
	if err := json.Unmarshal([]byte(args[2].String()), &in); err != nil {
		return errObj("bad inputs json")
	}
	w := &pool.Deposit{Cm: feDec(in.Cm), Amount: in.Amount, Nk: feDec(in.Nk), Rho: feDec(in.Rho)}
	return proveAndPack(ccs, pk, w)
}

type withdrawInputs struct {
	Sk        string `json:"sk"`
	Amount    uint64 `json:"amount"`
	Rho       string `json:"rho"`
	LeafIndex int    `json:"leafIndex"`
}

// proveShieldedWithdraw(pkB64, ccsB64, inputsJson) -> {proof, pub} — proves ownership of a note for a revealed amount.
func proveShieldedWithdraw(_ js.Value, args []js.Value) any {
	defer func() { recover() }()
	if len(args) < 3 {
		return errObj("proveShieldedWithdraw(pkB64, ccsB64, inputsJson)")
	}
	ccs, pk, e := loadKeys(args[0].String(), args[1].String())
	if e != "" {
		return errObj(e)
	}
	var in withdrawInputs
	if err := json.Unmarshal([]byte(args[2].String()), &in); err != nil {
		return errObj("bad inputs json")
	}
	sk := feDec(in.Sk)
	rho := feDec(in.Rho)
	nk := pool.HashFr(sk, pool.FeU64(pool.NkTag))
	cm := pool.HashFr3(pool.FeU64(in.Amount), nk, rho)
	nf := pool.HashFr(nk, rho)
	root, pathEls, pathIdx := pool.BuildTreePath(cm, in.LeafIndex)
	w := &pool.Withdraw{Root: root, Nullifier: nf, Amount: in.Amount, Sk: sk, Rho: rho}
	for i := 0; i < pool.TreeDepth; i++ {
		w.PathElements[i] = pathEls[i]
		w.PathIndices[i] = pathIdx[i]
	}
	return proveAndPack(ccs, pk, w)
}

// loadKeys decodes + reads a ccs + pk from base64.
func loadKeys(pkB64, ccsB64 string) (*cs.R1CS, groth16.ProvingKey, string) {
	pkBytes, err := base64.StdEncoding.DecodeString(pkB64)
	if err != nil {
		return nil, nil, "bad pk base64"
	}
	ccsBytes, err := base64.StdEncoding.DecodeString(ccsB64)
	if err != nil {
		return nil, nil, "bad ccs base64"
	}
	ccs := groth16.NewCS(ecc.BN254).(*cs.R1CS)
	if _, err := ccs.ReadFrom(bytes.NewReader(ccsBytes)); err != nil {
		return nil, nil, "ccs read: " + err.Error()
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
		return nil, nil, "pk read: " + err.Error()
	}
	return ccs, pk, ""
}

// proveAndPack proves a witness + returns {proof, pub} base64.
func proveAndPack(ccs *cs.R1CS, pk groth16.ProvingKey, w frontend.Circuit) any {
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		return errObj("witness: " + err.Error())
	}
	pubW, err := witness.Public()
	if err != nil {
		return errObj("public: " + err.Error())
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return errObj("prove: " + err.Error())
	}
	var pb bytes.Buffer
	if _, err := proof.WriteTo(&pb); err != nil {
		return errObj("proof serialize: " + err.Error())
	}
	pubBytes, err := pubW.MarshalBinary()
	if err != nil {
		return errObj("pub serialize: " + err.Error())
	}
	return map[string]any{"proof": b64(pb.Bytes()), "pub": b64(pubBytes)}
}

// mimcShielded(argsJsonArray) -> decimal hash. Lets the client derive nk/nf/commitments on-device (matching the
// circuit's MiMC) so it can compute which of its notes are spent + seal outputs — without revealing rho/nk.
func mimcShielded(_ js.Value, args []js.Value) any {
	defer func() { recover() }()
	if len(args) < 1 {
		return errObj("mimcShielded(jsonArrayOfDecimals)")
	}
	var ins []string
	if err := json.Unmarshal([]byte(args[0].String()), &ins); err != nil {
		return errObj("bad args json")
	}
	fes := make([]fr.Element, len(ins))
	for i, s := range ins {
		fes[i] = feDec(s)
	}
	// reuse the native MiMC over field elements (matches pool.HashFr/HashFr3 + the in-circuit hash)
	var out fr.Element
	switch len(fes) {
	case 2:
		out = pool.HashFr(fes[0], fes[1])
	case 3:
		out = pool.HashFr3(fes[0], fes[1], fes[2])
	default:
		return errObj("mimcShielded supports 2 or 3 inputs")
	}
	return map[string]any{"hash": out.String()}
}

func main() {
	js.Global().Set("proveShielded", js.FuncOf(proveShielded))
	js.Global().Set("proveShieldedDeposit", js.FuncOf(proveShieldedDeposit))
	js.Global().Set("proveShieldedWithdraw", js.FuncOf(proveShieldedWithdraw))
	js.Global().Set("mimcShielded", js.FuncOf(mimcShielded))
	select {} // keep the wasm alive to service calls
}

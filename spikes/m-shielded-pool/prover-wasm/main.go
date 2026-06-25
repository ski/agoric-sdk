// ADR 0014 M6e — the PRODUCTION client prover (compiled to WASM).
//
// Unlike the M4b demo (which ran the trusted setup in-WASM, ~30 s), this LOADS the ceremony proving key + the
// constraint system (shipped once after the M5b ceremony) and just PROVES — the realistic flow: ceremony once,
// ship pk, prove on the user's device in a few seconds. All note secrets (spend key sk, randomness rho) are
// DERIVED from the WebAuthn-PRF passkey output, so nothing secret is stored and nothing leaves the device.
//
// Run (node): node $(go-1.25)/lib/wasm/wasm_exec_node.js prover.wasm [passkey-prf-hex]
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"moimoi/shielded-pool/pool"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}

// deriveFr deterministically derives a field element from the passkey-PRF output + a label (no stored secret).
func deriveFr(prf []byte, label string) fr.Element {
	h := sha256.Sum256(append(append([]byte{}, prf...), []byte(label)...))
	var e fr.Element
	e.SetBytes(h[:]) // big-endian, reduced mod the scalar field
	return e
}

func main() {
	prf := []byte("passkey-prf-demo-output") // stand-in for the WebAuthn-PRF output
	if len(os.Args) > 1 {
		prf = []byte(os.Args[1])
	}

	// load the ceremony artifacts (shipped to the client; no in-WASM setup)
	ccs := groth16.NewCS(ecc.BN254)
	cf, err := os.Open("ceremony-ccs.bin")
	must(err)
	_, err = ccs.ReadFrom(cf)
	must(err)
	cf.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	pf, err := os.Open("ceremony-pk.bin")
	must(err)
	_, err = pk.ReadFrom(pf)
	must(err)
	pf.Close()
	fmt.Println("loaded ceremony pk + ccs (no in-WASM setup)")

	// derive ALL secrets from the passkey PRF — nothing stored, nothing leaves the device
	sk := deriveFr(prf, "sk")
	rhoIn := deriveFr(prf, "rho:in")
	rho0 := deriveFr(prf, "rho:0")
	rho1 := deriveFr(prf, "rho:1")
	nk := pool.HashFr(sk, pool.FeU64(pool.NkTag))
	nkB := pool.HashFr(deriveFr(prf, "recipient"), pool.FeU64(pool.NkTag))

	const amtIn, out0, out1, fee = 1000, 600, 397, 3
	cmIn := pool.HashFr3(pool.FeU64(amtIn), nk, rhoIn)
	nf := pool.HashFr(nk, rhoIn)
	cmOut0 := pool.HashFr3(pool.FeU64(out0), nk, rho0)
	cmOut1 := pool.HashFr3(pool.FeU64(out1), nkB, rho1)
	root, pathEls, pathIdx := pool.BuildTreePath(cmIn, 0)

	w := &pool.Transfer{
		Root: root, Nullifier: nf, CmOut0: cmOut0, CmOut1: cmOut1, Fee: fee,
		Sk: sk, AmtIn: amtIn, RhoIn: rhoIn,
		Amt0: out0, Nk0: nk, Rho0: rho0,
		Amt1: out1, Nk1: nkB, Rho1: rho1,
	}
	for i := 0; i < pool.TreeDepth; i++ {
		w.PathElements[i] = pathEls[i]
		w.PathIndices[i] = pathIdx[i]
	}

	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	must(err)
	pubW, err := witness.Public()
	must(err)

	proof, err := groth16.Prove(ccs, pk, witness)
	must(err)
	fmt.Println("proved (passkey-derived secrets, on-device)")

	// self-verify under the ceremony vk
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vf, err := os.Open("ceremony-vk.bin")
	must(err)
	_, err = vk.ReadFrom(vf)
	must(err)
	vf.Close()
	must(groth16.Verify(proof, vk, pubW))
	fmt.Println("VERIFIED under the ceremony vk")

	var pb bytes.Buffer
	_, err = proof.WriteTo(&pb)
	must(err)
	pubBytes, err := pubW.MarshalBinary()
	must(err)
	fmt.Println("PROOF=" + base64.StdEncoding.EncodeToString(pb.Bytes()))
	fmt.Println("PUB=" + base64.StdEncoding.EncodeToString(pubBytes))
}

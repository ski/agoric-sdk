// ADR 0014 #1 spike — generate a REAL depth-32 withdraw proof (the recipient retrieving a note from the pool).
// Mirrors prover-wasm-browser's proveShieldedWithdraw: nk=MiMC(sk,0), cm=MiMC(amount,nk,rho), nf=MiMC(nk,rho),
// Merkle path for (cm, leafIndex). rho is fixed (67890) to match prove-deposit so the note lines up.
//   go run . <amount> [sk] [leafIndex]   → {"proof","pub","nf","amount"}
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"

	"moimoi/shielded-pool/pool"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func argU64(i int, def uint64) uint64 {
	if len(os.Args) > i {
		n, e := strconv.ParseUint(os.Args[i], 10, 64)
		must(e)
		return n
	}
	return def
}

func main() {
	amount := argU64(1, 1000)
	skN := argU64(2, 12345)
	leafIndex := int(argU64(3, 0))

	sk := pool.FeU64(skN)
	rho := pool.FeU64(67890)
	nk := pool.HashFr(sk, pool.FeU64(pool.NkTag))
	cm := pool.HashFr3(pool.FeU64(amount), nk, rho)
	nf := pool.HashFr(nk, rho)
	root, pathEls, pathIdx := pool.BuildTreePath(cm, leafIndex)

	ccs := groth16.NewCS(ecc.BN254).(*cs.R1CS)
	_, e := ccs.ReadFrom(bytes.NewReader(read("../setup-assets/withdraw-ccs.bin")))
	must(e)
	pk := groth16.NewProvingKey(ecc.BN254)
	_, e = pk.ReadFrom(bytes.NewReader(read("../setup-assets/withdraw-pk.bin")))
	must(e)

	w := &pool.Withdraw{Root: root, Nullifier: nf, Amount: amount, Sk: sk, Rho: rho}
	for i := 0; i < pool.TreeDepth; i++ {
		w.PathElements[i] = pathEls[i]
		w.PathIndices[i] = pathIdx[i]
	}
	witness, e := frontend.NewWitness(w, ecc.BN254.ScalarField())
	must(e)
	pubW, e := witness.Public()
	must(e)
	proof, e := groth16.Prove(ccs, pk, witness)
	must(e)

	var pb bytes.Buffer
	_, e = proof.WriteTo(&pb)
	must(e)
	pubBytes, e := pubW.MarshalBinary()
	must(e)
	out, _ := json.Marshal(map[string]any{
		"proof":  base64.StdEncoding.EncodeToString(pb.Bytes()),
		"pub":    base64.StdEncoding.EncodeToString(pubBytes),
		"nf":     nf.String(),
		"amount": amount,
	})
	fmt.Println(string(out))
}

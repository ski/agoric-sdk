// ADR 0014 M7d — generate a REAL depth-32 deposit proof for the live write-path test (relay /shielded-offer).
// Picks arbitrary owner secrets (sk, rho), binds cm = MiMC(amount, nk, rho), proves with the depth-32 deposit key.
//   go run . <amount>   → {"proof","pub","cm","amount"} (base64 proof+pub)
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

func main() {
	amount := uint64(1000)
	if len(os.Args) > 1 {
		n, e := strconv.ParseUint(os.Args[1], 10, 64)
		must(e)
		amount = n
	}
	sk := pool.FeU64(12345)
	rho := pool.FeU64(67890)
	nk := pool.HashFr(sk, pool.FeU64(pool.NkTag))
	cm := pool.HashFr3(pool.FeU64(amount), nk, rho)

	ccs := groth16.NewCS(ecc.BN254).(*cs.R1CS)
	_, e := ccs.ReadFrom(bytes.NewReader(read("../setup-assets/deposit-ccs.bin")))
	must(e)
	pk := groth16.NewProvingKey(ecc.BN254)
	_, e = pk.ReadFrom(bytes.NewReader(read("../setup-assets/deposit-pk.bin")))
	must(e)

	w := &pool.Deposit{Cm: cm, Amount: amount, Nk: nk, Rho: rho}
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
		"cm":     cm.String(),
		"amount": amount,
	})
	fmt.Println(string(out))
}

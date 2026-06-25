// ADR 0014 M7d — generate a SELF-CONSISTENT prover-asset bundle (proving key + constraint system per circuit) that
// matches the CURRENT circuit definition (pool.TreeDepth). The browser prover (prover-wasm-browser) is compiled from
// the same `pool` package, so the keys this emits line up with the wasm exactly.
//
// This is a SINGLE-PARTY dev setup — fine for local end-to-end testing. PRODUCTION: the transfer proving key MUST
// come from the MPC ceremony (ceremony/) so no single party ever holds the toxic waste. (The depth-32 ceremony fix
// is the prerequisite for shipping production-depth transfer keys; deposit/withdraw are lower-stakes — deposit binds
// a public commitment, withdraw reveals the amount — but production should ceremony all three.)
//
//   cd setup-assets && go run .   → transfer-pk.bin transfer-ccs.bin deposit-*.bin withdraw-*.bin
package main

import (
	"bytes"
	"encoding/base64"
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

func wr(path string, w io.WriterTo) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		panic(err)
	}
}

// wrB64 serializes a gnark object and writes it base64-encoded (the form the deploy core-eval inlines as a VK string).
func wrB64(path string, w io.WriterTo) {
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(b.Bytes())), 0o644); err != nil {
		panic(err)
	}
}

func gen(name string, circuit frontend.Circuit) {
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		panic(fmt.Errorf("%s compile: %w", name, err))
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(fmt.Errorf("%s setup: %w", name, err))
	}
	wr(name+"-ccs.bin", ccs)
	wr(name+"-pk.bin", pk)
	wrB64(name+"-vk.b64", vk) // verifying key (base64) — the contract privateArg the deploy inlines
	fmt.Printf("%s: %d constraints → %s-pk.bin %s-ccs.bin %s-vk.b64 (%s)\n",
		name, ccs.GetNbConstraints(), name, name, name, time.Since(t0).Round(time.Millisecond))
}

func main() {
	gen("transfer", &pool.Transfer{})
	gen("deposit", &pool.Deposit{})
	gen("withdraw", &pool.Withdraw{})
	fmt.Println("done — base64 these into the app's public/shielded/ via build-browser-assets.sh")
}

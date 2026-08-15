// ADR 0014 M7d — offline correctness test for the depth-32 shielded-pool provers.
// For each circuit (deposit / withdraw / transfer) it does a full prove -> verify roundtrip against the SAME keys
// the live chain uses (setup-assets/<name>-{ccs,pk}.bin + the base64 <name>-vk.b64 the deploy inlines), then proves
// the VK rejects a forgery (the original proof verified against a tampered public input). This is exactly the check
// the on-chain zkVerify port performs, run locally with no chain.
package provetest

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"moimoi/shielded-pool/pool"
)

const nkTag = 0

func readInto(t *testing.T, rf io.ReaderFrom, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := rf.ReadFrom(bytes.NewReader(b)); err != nil {
		t.Fatalf("deserialize %s: %v", path, err)
	}
}

// loadKeys reads the constraint system, proving key, and the DEPLOYED (base64) verifying key for a circuit.
func loadKeys(t *testing.T, name string) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	t.Helper()
	ccs := groth16.NewCS(ecc.BN254)
	readInto(t, ccs, "../setup-assets/"+name+"-ccs.bin")
	pk := groth16.NewProvingKey(ecc.BN254)
	readInto(t, pk, "../setup-assets/"+name+"-pk.bin")
	vk := groth16.NewVerifyingKey(ecc.BN254)
	b64, err := os.ReadFile("../setup-assets/" + name + "-vk.b64")
	if err != nil {
		t.Fatalf("read %s-vk.b64: %v", name, err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b64)))
	if err != nil {
		t.Fatalf("b64 decode %s vk: %v", name, err)
	}
	if _, err := vk.ReadFrom(bytes.NewReader(raw)); err != nil {
		t.Fatalf("vk ReadFrom %s (compressed WriteTo form): %v", name, err)
	}
	return ccs, pk, vk
}

// proveVerify proves `valid` and asserts the deployed VK accepts it; then asserts the VK REJECTS the same proof
// checked against `forged` (an assignment with a tampered public input).
func proveVerify(t *testing.T, name string, valid, forged frontend.Circuit) {
	t.Helper()
	ccs, pk, vk := loadKeys(t, name)

	full, err := frontend.NewWitness(valid, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("%s: witness: %v", name, err)
	}
	pub, err := full.Public()
	if err != nil {
		t.Fatalf("%s: public witness: %v", name, err)
	}
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		t.Fatalf("%s: prove: %v", name, err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("%s: valid proof REJECTED by the deployed vk: %v", name, err)
	}
	t.Logf("%s: prove -> verify OK against the deployed vk", name)

	badPub, err := frontend.NewWitness(forged, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatalf("%s: forged public witness: %v", name, err)
	}
	if err := groth16.Verify(proof, vk, badPub); err == nil {
		t.Fatalf("%s: FORGERY ACCEPTED — proof verified against a tampered public input", name)
	}
	t.Logf("%s: forged public input correctly REJECTED", name)
}

// the note the live provers use (prove-deposit / prove-withdraw): sk=12345, rho=67890.
func noteSecrets() (sk, rho, nk fr.Element) {
	sk = pool.FeU64(12345)
	rho = pool.FeU64(67890)
	nk = pool.HashFr(sk, pool.FeU64(nkTag))
	return
}

func TestDepositProver(t *testing.T) {
	_, rho, nk := noteSecrets()
	amount := uint64(1000)
	cm := pool.HashFr3(pool.FeU64(amount), nk, rho)
	valid := &pool.Deposit{Cm: cm, Amount: amount, Nk: nk, Rho: rho}
	forged := &pool.Deposit{Cm: cm, Amount: amount + 1} // tamper the public amount
	proveVerify(t, "deposit", valid, forged)
}

func TestWithdrawProver(t *testing.T) {
	sk, rho, nk := noteSecrets()
	amount := uint64(1000)
	cm := pool.HashFr3(pool.FeU64(amount), nk, rho)
	nf := pool.HashFr(nk, rho)
	root, pathEls, pathIdx := pool.BuildTreePath(cm, 0)
	valid := &pool.Withdraw{Root: root, Nullifier: nf, Amount: amount, Sk: sk, Rho: rho}
	for i := 0; i < pool.TreeDepth; i++ {
		valid.PathElements[i] = pathEls[i]
		valid.PathIndices[i] = pathIdx[i]
	}
	forged := &pool.Withdraw{Root: root, Nullifier: nf, Amount: amount + 1} // tamper the public amount
	proveVerify(t, "withdraw", valid, forged)
}

func TestTransferProver(t *testing.T) {
	sk, rho, nk := noteSecrets()
	amtIn := uint64(1000)
	cmIn := pool.HashFr3(pool.FeU64(amtIn), nk, rho) // input note owner-bound to nk
	nf := pool.HashFr(nk, rho)
	root, pathEls, pathIdx := pool.BuildTreePath(cmIn, 0)

	amt0, amt1, fee := uint64(600), uint64(300), uint64(100) // conservation: 600+300+100 = 1000
	nk0 := pool.HashFr(pool.FeU64(22222), pool.FeU64(nkTag)) // recipient 0
	nk1 := pool.HashFr(pool.FeU64(33333), pool.FeU64(nkTag)) // recipient 1
	rho0, rho1 := pool.FeU64(11111), pool.FeU64(44444)
	cmOut0 := pool.HashFr3(pool.FeU64(amt0), nk0, rho0)
	cmOut1 := pool.HashFr3(pool.FeU64(amt1), nk1, rho1)

	valid := &pool.Transfer{
		Root: root, Nullifier: nf, CmOut0: cmOut0, CmOut1: cmOut1, Fee: fee,
		Sk: sk, AmtIn: amtIn, RhoIn: rho,
		Amt0: amt0, Nk0: nk0, Rho0: rho0, Amt1: amt1, Nk1: nk1, Rho1: rho1,
	}
	for i := 0; i < pool.TreeDepth; i++ {
		valid.PathElements[i] = pathEls[i]
		valid.PathIndices[i] = pathIdx[i]
	}
	forged := &pool.Transfer{Root: root, Nullifier: nf, CmOut0: cmOut0, CmOut1: cmOut1, Fee: fee + 1} // tamper public fee
	proveVerify(t, "transfer", valid, forged)
}

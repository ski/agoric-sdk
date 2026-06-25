// Package zkverify is the native confidential-value verifier (ADR 0014 Option 3): a deterministic
// Groth16/BN254 proof check exposed to swingset as a synchronous bridge port handler, run OFF the XS
// computron meter and ON consensus. VerifyBytes is the proven core (spikes/i-zk-confidential-value,
// ~0.8 ms); the bridge handler that wraps it lives in handler.go (M2b-4).
package zkverify

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

// VerifyBytes returns true iff proof is a valid Groth16 proof for vk over the public inputs pub.
// The chain bakes in vk (one per circuit version); each tx carries proof + pub (commitments + fee).
// Any malformed input or failed check returns (false, err) and never panics — the verifier fails closed.
func VerifyBytes(vkBytes, proofBytes, pubBytes []byte) (bool, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return false, err
	}
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return false, err
	}
	pub, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return false, err
	}
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return false, err
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		return false, err
	}
	return true, nil
}

package zkverify

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	"github.com/Agoric/agoric-sdk/golang/cosmos/vm"
)

// ADR 0014 M6b — a native MiMC(BN254) hash bridge port, so a swingset contract can maintain the commitment
// Merkle tree ON-CHAIN (recompute the root on each insert) using the EXACT hash the circuit uses — no
// MiMC-in-JS reimplementation risk, and no trusting an off-chain-seeded root. Deterministic, off the XS meter.

type mimcMessage struct {
	Type   string   `json:"type"`
	Inputs []string `json:"inputs"` // decimal field elements
}

type mimcResult struct {
	Hash string `json:"hash"` // decimal field element
}

// MimcBN254 is the only supported message type.
const MimcBN254 = "MIMC_BN254"

var _ vm.PortHandler = mimcHandler{}

type mimcHandler struct{}

// NewMimcReceiver returns the stateless mimcHash bridge port handler.
func NewMimcReceiver() mimcHandler { return mimcHandler{} }

func (mimcHandler) Receive(_ context.Context, str string) (string, error) {
	var msg mimcMessage
	if err := json.Unmarshal([]byte(str), &msg); err != nil {
		return "", fmt.Errorf("mimcHash: bad request json: %w", err)
	}
	if msg.Type != MimcBN254 {
		return "", fmt.Errorf("mimcHash: unknown message type %q", msg.Type)
	}
	h := bn254mimc.NewMiMC()
	for _, s := range msg.Inputs {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return "", fmt.Errorf("mimcHash: bad decimal input %q", s)
		}
		var e fr.Element
		e.SetBigInt(n)
		b := e.Bytes()
		h.Write(b[:])
	}
	var out fr.Element
	out.SetBytes(h.Sum(nil))
	bz, err := json.Marshal(mimcResult{Hash: out.String()})
	if err != nil {
		return "", err
	}
	return string(bz), nil
}

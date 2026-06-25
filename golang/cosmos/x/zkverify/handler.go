package zkverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Agoric/agoric-sdk/golang/cosmos/vm"
)

// message is the swingset bridge payload. vk/proof/pub are base64 (raw gnark-serialized bytes crossing JSON).
// vk is the circuit verifying key (baked into the chain per circuit version); proof + pub come from each tx.
type message struct {
	Type  string `json:"type"`
	Vk    string `json:"vk"`
	Proof string `json:"proof"`
	Pub   string `json:"pub"`
}

type verifyResult struct {
	Ok bool `json:"ok"`
}

// VerifyGroth16BN254 is the only supported message type (one circuit family for now).
const VerifyGroth16BN254 = "VERIFY_GROTH16_BN254"

var _ vm.PortHandler = portHandler{}

// portHandler is stateless — a deterministic pure verify, no keeper, no chain state read/written.
type portHandler struct{}

// NewReceiver returns the zkVerify bridge port handler (registered in app.go as port "zkVerify").
func NewReceiver() portHandler { return portHandler{} }

// Receive runs the native gnark verify OFF the XS computron meter and ON consensus (deterministic).
// A well-formed-but-invalid proof returns {ok:false} (a normal negative the contract branches on — fail closed,
// never a tx abort). A malformed request (bad base64) is a caller bug and surfaces as a bridge error.
func (portHandler) Receive(_ context.Context, str string) (string, error) {
	var msg message
	if err := json.Unmarshal([]byte(str), &msg); err != nil {
		return "", fmt.Errorf("zkVerify: bad request json: %w", err)
	}
	switch msg.Type {
	case VerifyGroth16BN254:
		vk, err := base64.StdEncoding.DecodeString(msg.Vk)
		if err != nil {
			return "", fmt.Errorf("zkVerify: bad vk base64: %w", err)
		}
		proof, err := base64.StdEncoding.DecodeString(msg.Proof)
		if err != nil {
			return "", fmt.Errorf("zkVerify: bad proof base64: %w", err)
		}
		pub, err := base64.StdEncoding.DecodeString(msg.Pub)
		if err != nil {
			return "", fmt.Errorf("zkVerify: bad pub base64: %w", err)
		}
		// fail closed: any VerifyBytes failure (soundness OR malformed artifact) collapses to ok:false.
		ok, _ := VerifyBytes(vk, proof, pub)
		bz, err := json.Marshal(verifyResult{Ok: ok})
		if err != nil {
			return "", err
		}
		return string(bz), nil
	default:
		return "", fmt.Errorf("zkVerify: unknown message type %q", msg.Type)
	}
}

package zkverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Real serialized artifacts from spikes/i-zk-confidential-value (gnark Groth16/BN254 Transfer circuit:
// MiMC commitments + conservation + 64-bit range). These are the exact bytes the bridge carries as base64.
const (
	vkB64    = "o9NRMsXElrd/HyA5Kd5bNMOTX/0uO/jp/PHtAxyOkgyAcZbitMjaFWExK+8EGxJxWANJaddx2Xn54Gf5fHxc0YoX7PxIz6EvmzmaDcvOdVbKombkaSppMLUn7loKIZd1FvMlXZ+C/eOZ2lupQbEgE+zKIzdm7IKaPgPqZ3r2+NapBcZ6rA5YkEO/Y5AwU8ujQDRZ2FutnNJqS/UMwziMFxb46KiS5lgLEXHVdhpNnlejQ+ZgFp9kgMAs7vdVdFtNyPslLJg3VMkf4BhZG2Q2KjlKqd8D4ujAUOfWHvuDFP2WnIcJwgE+BsSIYclJ2XToo+PmB6Up5kWW9a+fdXhrahMAlYtpwiodZo8vrE6Q6q02sT6fWkTh4pHQNd62HchlAAAABcVwffPd+WMVmrkkI9H3ptETm/4q3HN2Q0hivymlLoE/2udOkEVXkgKy42/xMc4ICVKiJIj4eu5t6C7W/44neZ3G1s+5tJbmBrzHF8M2VJVptVbjhXeOSUQP4yCUsWPpMJGFzN+fPeNvKga8mirRZr+PtyHPGrpVTOUpcuwjKc/whhpX5aB7Kzp8m1EPsPVcg+R+ivz+rgUix7XTAOP7ig8AAAAAAAAAAA=="
	proofB64 = "gb3QXra6eZraYJDlIrGY0dqPXu5LI2e2lETJAxFA2kaMaOD6dWIkNcYjlUYewt5UiNmyI+BuboIAwQJ/ODDCsCmB/SyWfo2wPjl1J5/okXfeLgndl4fExMtgK+v85oNupvDBb/po42xXqweX2nQhkbimUyHLrortAKllzjNyGQkAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	pubB64   = "AAAABAAAAAAAAAAEGROeAAUnLVu4IN42AIz8S7q/79n0SOsS+DVkeiR6xxQPGOmRidjBk6t6XlxcXnVGic5GIjHbO7znW1otHoo8dAgNVPjTYTj8ecVyE8prfrcyhXGbmFrT+NC3g2VkWFBPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM="
)

func recv(t *testing.T, vk, proof, pub string) verifyResult {
	t.Helper()
	req, _ := json.Marshal(message{Type: VerifyGroth16BN254, Vk: vk, Proof: proof, Pub: pub})
	out, err := NewReceiver().Receive(context.Background(), string(req))
	if err != nil {
		t.Fatalf("Receive errored on well-formed request: %v", err)
	}
	var r verifyResult
	if e := json.Unmarshal([]byte(out), &r); e != nil {
		t.Fatalf("bad result json %q: %v", out, e)
	}
	return r
}

func tamperB64(t *testing.T, b64 string, idx int) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	raw[idx] ^= 0xff
	return base64.StdEncoding.EncodeToString(raw)
}

// The loop-closer for ADR 0014: the exact bridge-port path verifies a real confidential-transfer proof,
// and fails CLOSED on tampered proof or public inputs — natively, off the XS meter.
func TestZkVerifyBridgePort(t *testing.T) {
	if r := recv(t, vkB64, proofB64, pubB64); !r.Ok {
		t.Fatal("valid proof must verify ok:true through the bridge port")
	}
	if r := recv(t, vkB64, tamperB64(t, proofB64, 8), pubB64); r.Ok {
		t.Fatal("tampered proof verified — port does not fail closed")
	}
	if r := recv(t, vkB64, proofB64, tamperB64(t, pubB64, len(mustDecode(t, pubB64))-1)); r.Ok {
		t.Fatal("tampered public inputs verified — port does not fail closed")
	}
}

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A malformed request (bad base64) is a caller bug and must surface as an error, not a silent ok:false.
func TestZkVerifyMalformedRequestErrors(t *testing.T) {
	req, _ := json.Marshal(message{Type: VerifyGroth16BN254, Vk: "!!not-base64!!", Proof: proofB64, Pub: pubB64})
	if _, err := NewReceiver().Receive(context.Background(), string(req)); err == nil {
		t.Fatal("expected error on bad base64 vk")
	}
}

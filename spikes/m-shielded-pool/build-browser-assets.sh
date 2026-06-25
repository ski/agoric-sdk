#!/usr/bin/env bash
# ADR 0014 M7d — build the browser shielded-prover asset bundle into the moimoi app's public dir.
#
# Emits exactly what prototype/src/shielded-prover.ts fetches lazily from /shielded/*:
#   wasm_exec.js            Go's browser wasm runtime (matches the build toolchain)
#   prover.wasm             GOOS=js GOARCH=wasm build of prover-wasm-browser (proveShielded{,Deposit,Withdraw}, mimcShielded)
#   pk.b64 ccs.b64          transfer circuit proving key + constraint system (base64)
#   deposit-pk.b64 deposit-ccs.b64 / withdraw-pk.b64 withdraw-ccs.b64
#
# The keys + wasm are built from the SAME `pool` package, so they line up with the current pool.TreeDepth.
# Run in WSL (needs the Go toolchain + the circuit sources). NOTE: these are SINGLE-PARTY dev keys — production
# transfer keys must come from the MPC ceremony (ceremony/), which requires the depth-32 ceremony fix.
#
#   ./build-browser-assets.sh [OUT_DIR]      OUT_DIR defaults to the moimoi public dir on the Windows mount.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

OUT="${1:-/mnt/c/Users/suhai/gitt/moimoi/prototype/public/shielded}"
mkdir -p "$OUT"

echo "==> generating self-consistent pk/ccs for all 3 circuits (current pool.TreeDepth)"
( cd setup-assets && go run . )

echo "==> building browser prover.wasm"
( cd prover-wasm-browser && GOOS=js GOARCH=wasm go build -o prover.wasm . )

echo "==> vendoring the Go wasm runtime + the prover"
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$OUT/wasm_exec.js"
cp prover-wasm-browser/prover.wasm "$OUT/prover.wasm"

b64() { base64 -w0 "$1" > "$2"; }
echo "==> base64-encoding keys into $OUT"
b64 setup-assets/transfer-pk.bin  "$OUT/pk.b64"
b64 setup-assets/transfer-ccs.bin "$OUT/ccs.b64"
b64 setup-assets/deposit-pk.bin   "$OUT/deposit-pk.b64"
b64 setup-assets/deposit-ccs.bin  "$OUT/deposit-ccs.b64"
b64 setup-assets/withdraw-pk.bin  "$OUT/withdraw-pk.b64"
b64 setup-assets/withdraw-ccs.bin "$OUT/withdraw-ccs.b64"

echo "==> done. bundle in $OUT:"
ls -la "$OUT"

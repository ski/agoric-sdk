# m-shielded-pool — ADR 0014 M4 (unlinkable confidential value, client-proved)

Upgrades M3 from "hidden amounts over raw, linkable commitments" to an UNLINKABLE shielded pool whose proofs are
generated CLIENT-SIDE in WASM and verified natively on consensus.

## M4a — the circuit (main.go)
gnark/BN254 Transfer-v2. Public [Root, Nullifier, CmOut0, CmOut1, Fee]; private amounts, rhos, Merkle path.
Proves: input note commitment opens to (amount, rho); Merkle membership of the input (hides WHICH leaf);
nullifier nf = MiMC(rho, 1) (unlinkable to the commitment); output commitments open; conservation
(in == out0 + out1 + fee); 64-bit range. **8079 constraints, verify ~0.8 ms native; forged nullifier + forged
root rejected.**

## M4b — the WASM prover
The whole gnark pipeline compiles + runs under GOOS=js GOARCH=wasm:
- size: **16.8 MB raw, ~3.6 MB gzip** (~3 MB brotli) — lazy-loaded on first transfer + cached by the PWA
  service worker (ADR 0015 S9), so it is a one-time first-use download.
- in WASM (node): compile 114 ms, **prove 3.69 s**, verify 17 ms. Setup (29.9 s) is a one-time ceremony shipped
  as the proving key, NOT per-transfer.
- secrets (amounts, rhos) are computed inside the prover and never leave it.
- The WASM-generated proof verifies natively (same proof/public inputs as the native run).
- **Remaining (thin):** derive rho deterministically from the WebAuthn-PRF passkey output (rho = H(prf, index))
  so notes need no stored secret. The proving (the hard part) is proven; this is a one-line wrapper.

## M4c — the contract + live proof (shielded-pool.contract.js, sp-core-eval.js)
Zoe shielded-pool contract for the new public shape: tracks valid Merkle roots + a NULLIFIER set (not
commitments). transfer verifies via the zkVerify bridge, binds to the AUTHENTICATED public inputs, checks
root-known + nullifier-unused, records outputs + fee. **Proven live with the WASM proof**
(published.shieldedPoolTest @ block 34):
- transfer before seeding the root -> rejected (unknown root)
- seed root, transfer            -> ACCEPTED (revealed nullifier, created 2 notes, fee 3)
- replay                         -> rejected (nullifier already used)
- tampered proof                 -> rejected (fail closed)

## Reproduce (WSL-native, fresh chain — register("zkVerify") is one-shot per chain)
    go run ./spikes/m-shielded-pool                              # M4a: native prove/verify + export vk/proof/pub
    GOOS=js GOARCH=wasm go build -o prover.wasm ./spikes/m-shielded-pool   # M4b
    node $(go env GOROOT-for-go1.25)/lib/wasm/wasm_exec_node.js prover.wasm  # runs prove in WASM, exports artifacts
    node spikes/m-shielded-pool/bundle.mjs                       # M4c: bundleID for the contract
    # re-genesis a fresh chain (force-kill the agd PARENT first — it respawns the node child on SIGTERM),
    # then install-bundle @sp-bundle.json, submit-proposal swingset-core-eval sp-permit.json sp-core-eval.js,
    # vote, query published.shieldedPoolTest.

## Chain-ops gotcha (learned here)
`agd start` RESPAWNS its node child on SIGTERM — `pkill -f entrypoint.js` is not enough to stop the chain; you
must `pkill -9 -f bin/agd` (the Go parent). And a bare `nohup agd & ` across `wsl -e` sessions is unreliable;
launch the long-lived chain via a managed background runner.

## Next (M4+ / M5)
- Passkey-PRF rho derivation (above). Real value escrow (deposit proves cm==MiMC(amount,blind)+escrows IST).
- In-contract Merkle tree (MiMC-in-JS or a `mimcHash` bridge port) so roots are computed on-chain, not seeded.
- M5: independent validator set (ADR 0041) — what makes the on-chain verify trustless.

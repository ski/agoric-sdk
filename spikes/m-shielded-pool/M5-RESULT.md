# M5 — making the verify TRUSTLESS (ADR 0014 / ADR 0041)

## M5b — Groth16 MPC trusted-setup ceremony ✅ (./ceremony)
The sharpest "cannot": a single-party setup leaves toxic waste (tau) with whoever ran it → they could forge
proofs and mint, regardless of validator count. Replaced with a multi-contribution ceremony (gnark `mpcsetup`,
Phase 1 powers-of-tau + Phase 2 circuit-specific; 3+3 independent contributions over serialized hand-offs). The
waste is unrecoverable unless EVERY contributor colluded. A proof under the CEREMONY vk verifies (same
`groth16.Verify` the zkVerify bridge calls) and soundness holds. The ceremony vk replaces the single-party vk
on-chain via gov (M5c).

## M5a — multi-validator BFT network ✅
`agd testnet start` (in-process) PANICS — it delegates to cosmos-sdk simapp's testnet path, which is not wired
for the SwingSet app. Working route: `agd testnet init-files -c 4 --single-host --keyring-backend test` (4
validators, staggered ports, persistent-peers) → start 4 separate `agd` processes sharing the genesis + the
SwingSet bootstrap config. Result: **4 bonded validators, node0 with 3 peers, consensus advancing** on chain-id
`agoriclocal4`. Every validator runs the SAME verify-bearing `agd` and re-executes the deterministic app, so a
zkVerify bridge call is replicated across all 4 and consensus only advances on agreement — replicated
verification. (Ports: node0 RPC :26657, node1 :26658, …; hold all 4 under one managed bg task with `wait`.)

## M5c — governance-locked rules (LARGELY ALREADY TRUE)
The vk is baked into the contract, which is installed ONLY via a gov `swingset-core-eval` proposal (what we used
throughout M3/M4) — so swapping the circuit/vk already requires a gov vote, not a quiet edit. Changing the native
verifier (the Go gnark code in `agd`) goes through cosmos `x/upgrade` gov proposals (`agd` ships x/upgrade). So
both layers of "the rules" are gov-gated by the validator/stakeholder set. Remaining polish: pin the vk as an
explicit gov-managed param (vs baked per-instance) for auditability.

## M5d — independent operators (ORGANIZATIONAL — the genuinely-remaining piece)
Trustless ultimately needs validators run by genuinely DIFFERENT parties (jurisdictions/interests) so collusion
is implausible — recruitment + economics, not code. Options (for ADR 0041): (i) own appchain with an external
validator community; (ii) diverse permissioned consortium (faster, weaker neutrality); (iii) upstream the
zkVerify port into Agoric + deploy on an existing decentralized chain (strongest neutrality, needs upstream
acceptance). M5a proves the network mechanics; M5d is the real-world decentralization those mechanics enable.

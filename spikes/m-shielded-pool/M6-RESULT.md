# M6 — hardening the shielded pool to product-grade (ADR 0014)

Goal (user directive): harden everything to product-grade, deferring ONLY the real independent validator set +
external ceremony (M5d) until the product is whole.

## M6a — owner-bound notes + spend authority ✅ (proven live, M6a in M6-RESULT covered by main.go)
Sapling-lite: spend key sk (passkey-derived) → nk = MiMC(sk,0); note cm = MiMC(amount, nk, rho); nullifier
nf = MiMC(nk, rho) needs sk. A wrong sk yields a different nk so cmIn isn't in the tree → proving fails: you
cannot spend a note you don't own. Public shape unchanged. 9729 constraints, verify 836µs; MPC ceremony re-run.

## M6b — on-chain Merkle tree via mimcHash bridge ✅ (proven live)
New native `mimcHash` BN254 bridge port. The contract builds a Tornado-style incremental tree ON-CHAIN using
the exact circuit hash — no off-chain seedRoot. Live: `rootsMatch:true` (contract root == circuit root);
before-deposit→reject, deposit+transfer→accept, replay→reject, tampered→reject.

## M6c — real value escrow ✅ (proven live, full round-trip)
Two value-layer circuits: deposit (1056 constraints, binds cm↔public amount) + withdraw (7681 constraints,
proves owned note for a revealed amount). Zoe contract: deposit gives N + deposit proof → escrow + insert;
withdraw verifies + wants N → atomicRearrange pays from the pool + burns the nullifier. Live
(published.shieldedEscrowTest @ block 29): deposit→escrowed 1000; withdraw→paidOut 1000, escrowed 0;
double-withdraw→rejected (nullifier). Demo uses a self-contained ZCFMint asset + faucet; production swaps
terms.Asset = IST (escrow code path identical).

## Remaining (M6d–M6f)
- **M6d — encrypted note discovery.** Attach note ciphertexts (amount, rho, nk) encrypted to the recipient's
  key so they can scan + decrypt incoming notes. Without it the pool is sound but unusable (you can't find your
  notes). Client encrypt/decrypt + contract stores ciphertexts alongside commitments. No new chain primitive.
- **M6e — client prover productionization.** WASM prover loads the CEREMONY pk (vs in-WASM setup); sk + rho
  derived from the WebAuthn-PRF passkey output; brotli + lazy-load + service-worker wiring into the moimoi client.
- **M6f — graduate to moimoi proper + vk-as-gov-param + audit prep.** Move circuit/prover/contracts from the
  agoric fork spikes into moimoi (contracts/UI/flows); pin vk as a gov param; nullifier-set storage strategy;
  ZK + value-contract audit before real funds.

Deferred (per directive, until the product is whole): real independent validators (M5d) + a real external MPC
ceremony with public transcript.

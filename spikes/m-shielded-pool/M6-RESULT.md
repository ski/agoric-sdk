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

## M6d — encrypted note discovery ✅
ECIES (X25519 ECDH + AES-256-GCM, Node built-in; same scheme as moimoi §F enc keys): each transfer attaches a
note ciphertext encrypting the opening (amount, nk, rho) to the recipient's X25519 pubkey. Recipients
trial-decrypt all on-chain ciphertexts; only theirs opens (auth tag gates). Demo (`notes/discover.mjs`): Alice +
Bob each recover exactly their note, eavesdropper recovers nothing. Contract wiring: deposit/transfer offerArgs
carry noteCiphertexts → published to a `notes` vstorage child (same proven publish path).

## M6e — production WASM client prover ✅
`prover-wasm` LOADS the ceremony pk + ccs (vs the M4b in-WASM 30 s setup) and proves on-device. ALL secrets
(spend key sk + randomness rho) derived from the WebAuthn-PRF output via sha256(prf, label) → fr — nothing
stored, nothing leaves the device. GOOS=js GOARCH=wasm: 14.5 MB raw / 3.16 MB gzip / ~2.7 MB brotli; in node it
loads the ceremony pk, proves a hardened transfer from a passkey seed, and self-verifies under the ceremony vk.

## Remaining
- **M6f — graduate to moimoi proper + vk-as-gov-param + audit prep.** Move circuit/prover/contracts from the
  agoric fork spikes into moimoi (contracts/UI/flows); wire brotli + lazy-load + service-worker (SW exists from
  0015 S9) for the prover; pin vk as a gov param; nullifier-set storage strategy; ZK + value-contract audit
  before real funds. (This is the cross-repo product integration.)

Deferred (per directive, until the product is whole): real independent validators (M5d) + a real external MPC
ceremony with public transcript.

Deferred (per directive, until the product is whole): real independent validators (M5d) + a real external MPC
ceremony with public transcript.

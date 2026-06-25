# l-confidential-transfer — ADR 0014 M3 proven live

A Zoe contract (the confidential-transfer shielded-note ledger) verified a real Groth16/BN254 proof through the
native `zkVerify` bridge port — **on consensus, off the XS computron meter** — and applied a conserved transition.

## Result (vstorage published.confidentialTransferTest, block 27)
| transfer | outcome | enforced by |
|---|---|---|
| valid | accepted: spent CommIn, created CommOut0 + CommOut1, fee 3 | SNARK verified via zkVerify bridge |
| tampered | rejected ("zkVerify: proof rejected") | native verify fails closed |
| double-spend (replay) | rejected ("input note already spent") | contract nullifier set |

Final ledger: commitments [CommIn, CommOut0, CommOut1], nullifiers [CommIn], feeTotal 3, transfers 1.
Conservation (in == out0 + out1 + fee) + 64-bit range are proven IN ZERO KNOWLEDGE by the SNARK; spend-once is the
contract; the ledger is bound to the verifier-AUTHENTICATED public inputs (handler echoes them, M3a).

## Pieces
- `confidential-transfer.contract.js` — the Zoe contract: deposit stub (seedNote), confidential `transfer`
  (offer → E(zkVerify).toBridge → ok + authenticated public inputs → spend/record/fee, offer-safe), withdraw TODO.
- `ct-core-eval.js` + `ct-permit.json` — the live driver (consumes bridgeManager+zoe+chainStorage; installs +
  starts the contract; seeds CommIn; runs valid/tampered/double-spend; writes outcomes to vstorage).
- `bundle.mjs` + `package.json` — bundles the contract with @endo/bundle-source (needs `import "@endo/init"` for
  harden+Compartment; a package.json declaring @endo/far so the compartment-mapper resolves deps).
- Depends on the `zkVerify` bridge port returning authenticated public inputs (golang/cosmos/x/zkverify, M3a).

## Reproduce (WSL-native, fresh chain)
Fresh chain is REQUIRED: `bridgeManager.register("zkVerify")` is one-shot per id and persists in chain state, so
a prior core-eval that registered it blocks a second. Re-genesis (`make scenario2-setup`), boot core-config, then:
    node spikes/l-confidential-transfer/bundle.mjs              # prints bundleID -> put in ct-core-eval.js
    agd tx swingset install-bundle @ct-bundle.json $FLAGS
    agd tx gov submit-proposal swingset-core-eval ct-permit.json ct-core-eval.js --deposit=50000000ubld $FLAGS
    agd tx gov vote 1 yes $FLAGS
    agd query vstorage data published.confidentialTransferTest --node=tcp://localhost:26657 -o json
Boot the long-lived chain via a managed background runner (a bare `nohup … &` across `wsl -e` sessions is flaky).

## Next (M3+ / M4)
- Real value escrow: deposit proves commitment == MiMC(amount, blind) + escrows IST; withdraw reveals + pays out.
- Merkle membership + nullifier derivation in the circuit (so notes are unlinkable, not raw commitments).
- Graduate the contract from this spike into moimoi proper.

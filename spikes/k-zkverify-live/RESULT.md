# k-zkverify-live — ADR 0014 Option 3 proven on a live chain

A swingset core-eval, running **on consensus**, invoked the native `zkVerify` bridge port and verified a
real confidential-transfer proof (gnark Groth16/BN254) **off the XS computron meter**.

## Result (queried from vstorage at block 13)

    published.zkVerifyProof =
    {"good":{"ok":true},"tampered":{"ok":false},"circuit":"groth16-bn254-transfer"}

- `good.ok = true`  — the real proof (from moimoi `spikes/i-zk-confidential-value`) verified.
- `tampered.ok = false` — a one-char-mutated proof failed CLOSED.

The verify ran in native Go inside `agd` (the cgo `agcosmosdaemon.node`), reached from the vat via
`E(bridgeManager).register("zkVerify").toBridge({type:"VERIFY_GROTH16_BN254", vk, proof, pub})`, deterministic
and consensus-safe. Standalone verify cost ~0.8 ms (spike i); the Go handler unit test
(`golang/cosmos/x/zkverify/handler_test.go`) also proves verify-ok + fail-closed.

## The pieces (committed on branch `moimoi/zkverify-device`)
- `golang/cosmos/x/zkverify/{zkverify.go,handler.go,handler_test.go}` — verify core + stateless bridge PortHandler.
- `golang/cosmos/app/app.go` — `MustRegisterPortHandler("zkVerify", …)` + `ZkVerifyPort` in `cosmosInitAction`.
- `packages/internal/src/config.js` — `BridgeId.ZK_VERIFY = "zkVerify"`.
- This dir — `zkverify-core-eval.js` (+ `zkverify-permit.json`): the live proof core-eval.

## Reproduce (WSL2-native, no Docker)
    export PATH=/usr/local/go/bin:$PATH
    cd ~/agoric-sdk && git checkout moimoi/zkverify-device
    yarn install && yarn build && (cd packages/cosmic-swingset && make)   # builds ./bin/agd (commit c596c96)
    go test ./golang/cosmos/x/zkverify/                                   # native handler proof

    cd packages/cosmic-swingset
    make scenario2-setup                                                  # genesis (chain-id agoriclocal)
    # GOTCHA: `jq` is NOT installed in this WSL, so scenario2-setup's voting_period edit silently fails
    # (genesis stays at the 36h default). Patch it directly (genesis only applies at re-genesis):
    python3 -c 'import json;p="t1/n0/config/genesis.json";g=json.load(open(p));g["app_state"]["gov"]["params"].update({"voting_period":"10s","expedited_voting_period":"10s","max_deposit_period":"10s"});json.dump(g,open(p,"w"))'

    GH=$(sha256sum t1/n0/config/genesis.json | cut -d" " -f1)
    CHAIN_BOOTSTRAP_VAT_CONFIG="$PWD/../vm-config/decentral-core-config.json" GENESIS_HASH=$GH \
      PATH="$PWD/bin:$PATH" ../../bin/agd --home=t1/n0 start --log_level=warn &   # core-config: 0 coreProposals, fast boot, still has bridgeManager+chainStorage

    FLAGS="--from bootstrap --keyring-backend=test --home=t1/bootstrap --chain-id=agoriclocal --node=tcp://localhost:26657 --gas auto --gas-adjustment 1.6 -y"
    agd tx gov submit-proposal swingset-core-eval ../../spikes/k-zkverify-live/zkverify-permit.json ../../spikes/k-zkverify-live/zkverify-core-eval.js --title=zk --description=zk --deposit=50000000ubld $FLAGS
    agd tx gov vote 1 yes $FLAGS                                          # single validator; passes in ~10s
    agd query vstorage data published.zkVerifyProof --node=tcp://localhost:26657 -o json

## Chain-ops notes
- `agd` is `~/agoric-sdk/bin/agd`; the chain runs as `node packages/cosmic-swingset/src/entrypoint.js … start`
  (the Node controller loads the cgo `agcosmosdaemon.node` that contains the Go verifier).
- `jq` missing in WSL → install it (`apt-get install jq`) to make scenario2-setup's genesis edits work.
- Editing `genesis.json` only matters at re-genesis; a restart replays from `data/`.

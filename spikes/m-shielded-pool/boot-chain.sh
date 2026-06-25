#!/usr/bin/env bash
# ADR 0014 M7d — boot a fresh WSL-native scenario2 chain (patched agd: zkVerify + mimcHash ports) for the live wire.
# Fresh genesis is MANDATORY: the bridge-port register() is one-shot, so a re-run on stale state 409s.
set -x
export PATH=/usr/local/go/bin:$HOME/agoric-sdk/bin:$PATH
cd ~/agoric-sdk/packages/cosmic-swingset

# clear any half-dead chain (the node child survives a bin/agd kill — kill both, confirm the RPC port is free)
pkill -9 -f entrypoint.js 2>/dev/null; pkill -9 -f 'bin/agd' 2>/dev/null; pkill -9 -f 'agd.*start' 2>/dev/null
sleep 3
rm -rf t1

make scenario2-setup
# voting_period → 10s so the deploy gov-proposal passes in one session (jq edit may no-op; force it directly)
python3 -c 'import json;p="t1/n0/config/genesis.json";g=json.load(open(p));g["app_state"]["gov"]["params"].update({"voting_period":"10s","expedited_voting_period":"10s","max_deposit_period":"10s"});json.dump(g,open(p,"w"))'
sed -i "s#127.0.0.1:26657#0.0.0.0:26657#" t1/n0/config/config.toml

GH=$(sha256sum t1/n0/config/genesis.json | cut -d" " -f1)
# decentral-devnet-config bootstraps the walletFactory + provisionPool + smart-wallet (needed for the WRITE path:
# worker→relay→smart-wallet→contract). Heavier than core-config (~several min) but the contract write path needs it.
exec env \
  CHAIN_BOOTSTRAP_VAT_CONFIG="$PWD/../vm-config/${BOOT_CONFIG:-decentral-devnet-config}.json" \
  GENESIS_HASH="$GH" \
  ~/agoric-sdk/bin/agd --home=t1/n0 start --log_level=warn

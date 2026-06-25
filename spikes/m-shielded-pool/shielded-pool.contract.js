// @ts-nocheck
// ADR 0014 M4c — shielded-pool Zoe contract (unlinkable notes).
//
// Upgrades the M3 ledger to the M4 circuit's public shape [Root, Nullifier, CmOut0, CmOut1, Fee]. A spend now
// proves Merkle membership of the input note and reveals a NULLIFIER (derived from the note secret), NOT the
// input commitment — so spends are UNLINKABLE. The contract keys spend-once on the nullifier, and checks the
// proof's Merkle root against roots it knows.
//
// privateArgs: { zkVerify, vk (base64 for the M4 circuit), storageNode? }
//
// Spike simplification: validRoots are recorded via seedRoot (root computed off-chain by the prover). Production
// maintains the tree IN the contract — recompute the root on each insert, via MiMC-in-JS or a `mimcHash` bridge
// port (the same native-host pattern as zkVerify). The transfer mechanism below is identical either way.
import { E, Far } from '@endo/far';

const TYPE = 'VERIFY_GROTH16_BN254';

export const start = async (zcf, privateArgs) => {
  const { zkVerify, vk, storageNode } = privateArgs;
  assert(zkVerify, 'privateArgs.zkVerify required');
  assert(typeof vk === 'string', 'privateArgs.vk required');

  const validRoots = new Set(); // Merkle roots the pool recognizes
  const nullifiers = new Set(); // spent nullifiers (NOT commitments → unlinkable)
  const commitments = new Set(); // output note commitments recorded
  let feeTotal = 0n;
  let transfers = 0;

  const publish = async () => {
    if (!storageNode) return;
    await E(storageNode).setValue(
      JSON.stringify({
        validRoots: [...validRoots],
        nullifiers: [...nullifiers],
        commitments: [...commitments],
        feeTotal: String(feeTotal),
        transfers,
      }),
    );
  };

  const seedRoot = async root => {
    validRoots.add(String(root));
    await publish();
    return 'seeded';
  };

  const transferHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      assert(proof && pub, 'transfer needs offerArgs { proof, pub }');

      const res = await E(zkVerify).toBridge({ type: TYPE, vk, proof, pub });
      assert(res && res.ok, 'zkVerify: proof rejected (invalid or malformed)');

      // authenticated public inputs: [Root, Nullifier, CmOut0, CmOut1, Fee]
      const [root, nf, cmOut0, cmOut1, fee] = res.public;
      assert(validRoots.has(root), 'unknown or stale merkle root');
      assert(!nullifiers.has(nf), 'double-spend: nullifier already used');

      nullifiers.add(nf);
      commitments.add(cmOut0);
      commitments.add(cmOut1);
      feeTotal += BigInt(fee);
      transfers += 1;

      seat.exit();
      await publish();
      return harden({ ok: true, nullifier: nf, created: [cmOut0, cmOut1], fee });
    } catch (err) {
      seat.exit(err);
      throw err;
    }
  };

  const publicFacet = Far('ShieldedPool public', {
    makeTransferInvitation: () => zcf.makeInvitation(transferHandler, 'shielded-transfer'),
    getState: () =>
      harden({
        validRoots: [...validRoots],
        nullifiers: [...nullifiers],
        commitments: [...commitments],
        feeTotal: String(feeTotal),
        transfers,
      }),
  });
  const creatorFacet = Far('ShieldedPool creator', { seedRoot });

  await publish();
  return harden({ publicFacet, creatorFacet });
};
harden(start);

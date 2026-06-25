// @ts-nocheck
// ADR 0014 M6b — shielded-pool contract with an ON-CHAIN incremental Merkle tree.
//
// Removes the M4c seedRoot trust: the contract builds the commitment tree ITSELF using the native mimcHash
// bridge port (the exact MiMC the circuit uses), so a transfer's proof root must match a root the contract
// actually computed. deposit inserts a note; transfer verifies the proof, checks the input root is one the
// contract produced, marks the nullifier, and inserts the two output notes (they become spendable).
//
// privateArgs: { zkVerify, mimcHash, vk (base64), storageNode? }
import { E, Far } from '@endo/far';

const VERIFY = 'VERIFY_GROTH16_BN254';
const MIMC = 'MIMC_BN254';
const DEPTH = 8;

export const start = async (zcf, privateArgs) => {
  const { zkVerify, mimcHash, vk, storageNode } = privateArgs;
  assert(zkVerify && mimcHash, 'privateArgs.zkVerify + mimcHash required');
  assert(typeof vk === 'string', 'privateArgs.vk required');

  const hash2 = async (a, b) => {
    const r = await E(mimcHash).toBridge({ type: MIMC, inputs: [String(a), String(b)] });
    return r.hash;
  };

  // empty-subtree hashes: zeros[0] = 0, zeros[i] = MiMC(zeros[i-1], zeros[i-1])
  const zeros = ['0'];
  for (let i = 1; i <= DEPTH; i += 1) zeros.push(await hash2(zeros[i - 1], zeros[i - 1]));

  // incremental (append-only) Merkle tree — Tornado/Semaphore style. Matches the circuit's leaf-0-first,
  // empty-leaves-zero tree, so the contract root equals the circuit root with no seeding.
  const filledSubtrees = zeros.slice(0, DEPTH);
  let nextIndex = 0;
  let root = zeros[DEPTH];
  const rootHistory = new Set([root]);
  const nullifiers = new Set();
  let leafCount = 0;

  const insert = async leaf => {
    assert(nextIndex < 1 << DEPTH, 'tree full');
    let idx = nextIndex;
    let cur = String(leaf);
    for (let level = 0; level < DEPTH; level += 1) {
      let left;
      let right;
      if (idx % 2 === 0) {
        left = cur;
        right = zeros[level];
        filledSubtrees[level] = cur;
      } else {
        left = filledSubtrees[level];
        right = cur;
      }
      cur = await hash2(left, right);
      idx = Math.floor(idx / 2);
    }
    root = cur;
    rootHistory.add(root);
    nextIndex += 1;
    leafCount += 1;
    return root;
  };

  const publish = async () => {
    if (!storageNode) return;
    await E(storageNode).setValue(
      JSON.stringify({ root, leaves: leafCount, roots: rootHistory.size, nullifiers: [...nullifiers] }),
    );
  };

  // deposit stub: insert a note commitment + compute the new root on-chain (real IST escrow is M6c).
  const deposit = async commitment => {
    const r = await insert(commitment);
    await publish();
    return harden({ ok: true, root: r, index: nextIndex - 1 });
  };

  const transferHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      assert(proof && pub, 'transfer needs offerArgs { proof, pub }');
      const res = await E(zkVerify).toBridge({ type: VERIFY, vk, proof, pub });
      assert(res && res.ok, 'zkVerify: proof rejected (invalid or malformed)');

      const [pRoot, nf, cmOut0, cmOut1, fee] = res.public; // authenticated
      assert(rootHistory.has(pRoot), 'unknown merkle root (note not in the contract tree)');
      assert(!nullifiers.has(nf), 'double-spend: nullifier already used');

      nullifiers.add(nf);
      await insert(cmOut0); // outputs become spendable notes
      await insert(cmOut1);

      seat.exit();
      await publish();
      return harden({ ok: true, nullifier: nf, created: [cmOut0, cmOut1], fee, root });
    } catch (err) {
      seat.exit(err);
      throw err;
    }
  };

  const publicFacet = Far('ShieldedPoolTree public', {
    makeTransferInvitation: () => zcf.makeInvitation(transferHandler, 'shielded-transfer'),
    getState: () => harden({ root, leaves: leafCount, roots: rootHistory.size, nullifiers: [...nullifiers] }),
  });
  const creatorFacet = Far('ShieldedPoolTree creator', { deposit });

  await publish();
  return harden({ publicFacet, creatorFacet });
};
harden(start);

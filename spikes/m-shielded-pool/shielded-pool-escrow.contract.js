// @ts-nocheck
// ADR 0014 M6c — shielded pool with REAL IST escrow. Extends the on-chain-tree pool (M6b) with a value layer:
//   - deposit: give N IST (proposal give {Asset}) + a deposit proof binding cm to N -> escrow the IST + insert cm.
//   - transfer: confidential 1-in/2-out (M6a/M6b) -> no value moves, only the commitment set changes.
//   - withdraw: a withdraw proof for a revealed amount + want {Asset: N} -> pay N IST from the pool, burn (nf).
// Conservation across the lifecycle: IST in == notes' value; transfers preserve it in zero knowledge; withdraw
// pays out exactly the proven amount. nullifiers prevent double-spend; the tree root is computed on-chain.
//
// terms: { Asset: IssuerKeyword for IST }   privateArgs: { zkVerify, mimcHash, transferVk, depositVk, withdrawVk, storageNode? }
import { E, Far } from '@endo/far';
import { AmountMath } from '@agoric/ertp';

const VERIFY = 'VERIFY_GROTH16_BN254';
const MIMC = 'MIMC_BN254';
const DEPTH = 8;

export const start = async (zcf, privateArgs) => {
  const { zkVerify, mimcHash, transferVk, depositVk, withdrawVk, storageNode } = privateArgs;
  assert(zkVerify && mimcHash, 'zkVerify + mimcHash required');
  const { Asset: assetBrand } = zcf.getTerms().brands;

  const hash2 = async (a, b) => (await E(mimcHash).toBridge({ type: MIMC, inputs: [String(a), String(b)] })).hash;
  const verify = async (vk, proof, pub) => E(zkVerify).toBridge({ type: VERIFY, vk, proof, pub });

  // on-chain incremental Merkle tree (M6b)
  const zeros = ['0'];
  for (let i = 1; i <= DEPTH; i += 1) zeros.push(await hash2(zeros[i - 1], zeros[i - 1]));
  const filledSubtrees = zeros.slice(0, DEPTH);
  let nextIndex = 0;
  let root = zeros[DEPTH];
  const rootHistory = new Set([root]);
  const nullifiers = new Set();

  const insert = async leaf => {
    assert(nextIndex < 1 << DEPTH, 'tree full');
    let idx = nextIndex;
    let cur = String(leaf);
    for (let level = 0; level < DEPTH; level += 1) {
      let left;
      let right;
      if (idx % 2 === 0) { left = cur; right = zeros[level]; filledSubtrees[level] = cur; }
      else { left = filledSubtrees[level]; right = cur; }
      cur = await hash2(left, right);
      idx = Math.floor(idx / 2);
    }
    root = cur;
    rootHistory.add(root);
    nextIndex += 1;
    return root;
  };

  // the pool's escrowed IST lives on a single internal seat
  const { zcfSeat: pool } = zcf.makeEmptySeatKit();
  const poolBalance = () => pool.getAmountAllocated('Asset', assetBrand);

  const publish = async () => {
    if (!storageNode) return;
    await E(storageNode).setValue(
      JSON.stringify({ root, leaves: nextIndex, roots: rootHistory.size, nullifiers: [...nullifiers], escrowed: String(poolBalance().value) }),
    );
  };

  // deposit: give N IST + a deposit proof binding cm to N -> escrow + insert cm
  const depositHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      const res = await verify(depositVk, proof, pub);
      assert(res && res.ok, 'deposit: proof rejected');
      const [cm, amount] = res.public; // authenticated [Cm, Amount]
      const given = seat.getAmountAllocated('Asset', assetBrand);
      assert(given.value === BigInt(amount), `deposit: gave ${given.value} but proof commits ${amount}`);
      zcf.atomicRearrange(harden([[seat, pool, { Asset: given }]])); // escrow the IST
      await insert(cm);
      seat.exit();
      await publish();
      return harden({ ok: true, cm, amount, root });
    } catch (err) { seat.exit(err); throw err; }
  };

  // withdraw: a withdraw proof for a revealed amount + want N IST -> pay from pool, burn (nf)
  const withdrawHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      const res = await verify(withdrawVk, proof, pub);
      assert(res && res.ok, 'withdraw: proof rejected');
      const [pRoot, nf, amount] = res.public; // authenticated [Root, Nullifier, Amount]
      assert(rootHistory.has(pRoot), 'withdraw: unknown merkle root');
      assert(!nullifiers.has(nf), 'withdraw: nullifier already used');
      const want = AmountMath.make(assetBrand, BigInt(amount));
      nullifiers.add(nf);
      zcf.atomicRearrange(harden([[pool, seat, { Asset: want }]])); // pay out from the pool
      seat.exit();
      await publish();
      return harden({ ok: true, nullifier: nf, amount });
    } catch (err) { seat.exit(err); throw err; }
  };

  // confidential transfer (M6a/M6b): no IST moves, only the commitment set
  const transferHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      const res = await verify(transferVk, proof, pub);
      assert(res && res.ok, 'transfer: proof rejected');
      const [pRoot, nf, cmOut0, cmOut1, fee] = res.public;
      assert(rootHistory.has(pRoot), 'transfer: unknown merkle root');
      assert(!nullifiers.has(nf), 'transfer: nullifier already used');
      nullifiers.add(nf);
      await insert(cmOut0);
      await insert(cmOut1);
      seat.exit();
      await publish();
      return harden({ ok: true, nullifier: nf, created: [cmOut0, cmOut1], fee, root });
    } catch (err) { seat.exit(err); throw err; }
  };

  const publicFacet = Far('ShieldedPool public', {
    makeDepositInvitation: () => zcf.makeInvitation(depositHandler, 'shield-deposit'),
    makeTransferInvitation: () => zcf.makeInvitation(transferHandler, 'shield-transfer'),
    makeWithdrawInvitation: () => zcf.makeInvitation(withdrawHandler, 'shield-withdraw'),
    getState: () => harden({ root, leaves: nextIndex, roots: rootHistory.size, nullifiers: [...nullifiers], escrowed: String(poolBalance().value) }),
  });

  await publish();
  return harden({ publicFacet });
};
harden(start);

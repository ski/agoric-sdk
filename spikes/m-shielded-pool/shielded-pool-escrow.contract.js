// @ts-nocheck
// ADR 0014 M6c — shielded pool with REAL value escrow (deposit / transfer / withdraw).
//
//   - deposit: give N Asset (proposal give {Asset}) + a deposit proof binding cm to N -> escrow + insert cm.
//   - transfer: confidential 1-in/2-out (M6a/M6b) -> no value moves, only the commitment set changes.
//   - withdraw: a withdraw proof for a revealed amount + want {Asset: N} -> pay N from the pool, burn (nf).
//
// Value-layer is asset-agnostic: the escrow uses zcf.atomicRearrange over a Brand. For a self-contained demo
// the contract mints its own "Shield" asset (+ a test faucet); in production terms.Asset = IST and the faucet
// is dropped — the deposit/withdraw/escrow code is byte-identical. Root computed on-chain (M6b); nullifiers
// prevent double-spend; owner-bound notes (M6a).
//
// privateArgs: { zkVerify, mimcHash, transferVk, depositVk, withdrawVk, storageNode? }
import { E, Far } from '@endo/far';
import { AmountMath } from '@agoric/ertp';

const VERIFY = 'VERIFY_GROTH16_BN254';
const MIMC = 'MIMC_BN254';
const DEPTH = 8;

export const start = async (zcf, privateArgs) => {
  const { zkVerify, mimcHash, transferVk, depositVk, withdrawVk, storageNode } = privateArgs;
  assert(zkVerify && mimcHash, 'zkVerify + mimcHash required');

  // self-contained demo asset (production: terms.Asset = IST, drop the mint + faucet)
  const shieldMint = await zcf.makeZCFMint('Shield');
  const { brand: assetBrand } = shieldMint.getIssuerRecord();

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

  const { zcfSeat: pool } = zcf.makeEmptySeatKit();
  const { zcfSeat: reserve } = zcf.makeEmptySeatKit(); // M7a: protocol fees accrue here
  const escrowed = () => pool.getAmountAllocated('Asset', assetBrand).value;
  const reserved = () => reserve.getAmountAllocated('Asset', assetBrand).value;

  // M6d: encrypted note ciphertexts (opening encrypted to the recipient's key), published so recipients can
  // scan + trial-decrypt their own notes. Opaque to everyone else; unlinkable to commitments on-chain.
  const noteCiphertexts = [];
  const notesNode = storageNode ? E(storageNode).makeChildNode('notes') : undefined;
  const publishNotes = async cts => {
    if (!cts || !cts.length) return;
    for (const ct of cts) noteCiphertexts.push(ct);
    if (notesNode) await E(notesNode).setValue(JSON.stringify(noteCiphertexts));
  };

  const publish = async () => {
    if (!storageNode) return;
    await E(storageNode).setValue(
      JSON.stringify({ root, leaves: nextIndex, roots: rootHistory.size, nullifiers: [...nullifiers], escrowed: String(escrowed()), reserve: String(reserved()), notes: noteCiphertexts.length }),
    );
  };

  const depositHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      const res = await verify(depositVk, proof, pub);
      assert(res && res.ok, 'deposit: proof rejected');
      const [cm, amount] = res.public; // authenticated [Cm, Amount]
      const given = seat.getAmountAllocated('Asset', assetBrand);
      assert(given.value === BigInt(amount), `deposit: gave ${given.value}, proof commits ${amount}`);
      zcf.atomicRearrange(harden([[seat, pool, { Asset: given }]]));
      await insert(cm);
      await publishNotes((offerArgs || {}).noteCiphertexts);
      seat.exit();
      await publish();
      return harden({ ok: true, cm, amount, root, escrowed: String(escrowed()), reserve: String(reserved()) });
    } catch (err) { seat.exit(err); throw err; }
  };

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
      zcf.atomicRearrange(harden([[pool, seat, { Asset: want }]]));
      seat.exit();
      await publish();
      return harden({ ok: true, nullifier: nf, amount, escrowed: String(escrowed()), reserve: String(reserved()) });
    } catch (err) { seat.exit(err); throw err; }
  };

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
      // M7a: the fee leaves the shielded set (outputs sum to amtIn - fee), so its escrowed value is no longer
      // backed by a note — route it from the pool to the protocol reserve, keeping the pool exactly note-backed.
      const feeV = BigInt(fee);
      if (feeV > 0n) {
        zcf.atomicRearrange(harden([[pool, reserve, { Asset: AmountMath.make(assetBrand, feeV) }]]));
      }
      await publishNotes((offerArgs || {}).noteCiphertexts);
      seat.exit();
      await publish();
      return harden({ ok: true, nullifier: nf, created: [cmOut0, cmOut1], fee, reserve: String(reserved()), root });
    } catch (err) { seat.exit(err); throw err; }
  };

  // test faucet: mint N Asset to a fresh payment (production: dropped; users hold real IST)
  const faucet = async value => {
    const { zcfSeat, userSeat } = zcf.makeEmptySeatKit();
    shieldMint.mintGains(harden({ Asset: AmountMath.make(assetBrand, BigInt(value)) }), zcfSeat);
    zcfSeat.exit();
    return E(userSeat).getPayout('Asset');
  };

  const publicFacet = Far('ShieldedPool public', {
    getAssetIssuer: () => shieldMint.getIssuerRecord().issuer,
    getAssetBrand: () => assetBrand,
    makeDepositInvitation: () => zcf.makeInvitation(depositHandler, 'shield-deposit'),
    makeTransferInvitation: () => zcf.makeInvitation(transferHandler, 'shield-transfer'),
    makeWithdrawInvitation: () => zcf.makeInvitation(withdrawHandler, 'shield-withdraw'),
    getState: () => harden({ root, leaves: nextIndex, roots: rootHistory.size, nullifiers: [...nullifiers], escrowed: String(escrowed()), reserve: String(reserved()) }),
  });
  const creatorFacet = Far('ShieldedPool creator', { faucet });

  await publish();
  return harden({ publicFacet, creatorFacet });
};
harden(start);

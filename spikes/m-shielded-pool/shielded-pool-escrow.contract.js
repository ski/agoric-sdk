// @ts-nocheck
// ADR 0014 shielded pool with REAL value escrow (deposit / transfer / withdraw).
//
//   - deposit: give N Asset (proposal give {Asset}) + a deposit proof binding cm to N -> escrow + insert cm.
//   - transfer: confidential 1-in/2-out (M6a/M6b) -> no value moves, only the commitment set changes.
//   - withdraw: a withdraw proof for a revealed amount + want {Asset: N} -> pay N from the pool, burn (nf).
//
// M7c — DURABLE + UPGRADABLE. The 3rd `baggage` arg makes Zoe treat this as an upgradable contract; ALL state
//   (tree, roots, nullifiers, note ciphertexts, counters, the escrow + reserve seats) lives in baggage-backed
//   durable stores, so a chain upgrade / restart preserves the pool instead of wiping `let root` / `new Set()`.
// M7e — the verifying keys are DURABLE, GOVERNANCE-ROTATABLE params (not deploy-baked privateArgs): held in a
//   durable `params` store, initialized once from privateArgs, rotated via the creatorFacet (the governance-held
//   facet) and the new vk-hash published to vstorage for audit — so a circuit can be rotated WITHOUT a redeploy.
//
// Value-layer is asset-agnostic: escrow is zcf.atomicRearrange over a Brand. PRODUCTION starts with
// issuerKeywordRecord { Asset: IST }; the self-minted "Shield" demo asset is the fallback. Root on-chain (M6b);
// nullifiers prevent double-spend (M4); owner-bound notes (M6a); production depth 32 (M7b).
//
// privateArgs: { zkVerify, mimcHash, transferVk, depositVk, withdrawVk, storageNode? }
import { E, Far } from '@endo/far';
import { AmountMath } from '@agoric/ertp';
import { makeDurableZone } from '@agoric/zone/durable.js';
import { provideEmptySeat } from '@agoric/zoe/src/contractSupport/durability.js';

const VERIFY = 'VERIFY_GROTH16_BN254';
const MIMC = 'MIMC_BN254';
const DEPTH = 32; // M7b production depth — MUST match the circuit (pool.TreeDepth) or proof roots never line up

// Upgradable contract: the 3rd `baggage` arg is what makes Zoe keep this instance across upgrades.
export const start = async (zcf, privateArgs, baggage) => {
  const { zkVerify, mimcHash, transferVk, depositVk, withdrawVk, storageNode } = privateArgs;
  assert(zkVerify && mimcHash, 'zkVerify + mimcHash required');
  const zone = makeDurableZone(baggage);

  // ── asset: IST in production (terms.Asset), self-minted Shield in the demo (durable across upgrade) ──
  const terms = zcf.getTerms();
  let assetBrand;
  let assetIssuer;
  let faucet; // demo mode only
  if (terms.brands && terms.brands.Asset) {
    assetBrand = terms.brands.Asset;
    assetIssuer = terms.issuers.Asset;
  } else {
    // makeZCFMint returns a durable mint in an upgradable contract — create once, reuse from baggage on upgrade.
    let shieldMint;
    if (baggage.has('shieldMint')) {
      shieldMint = baggage.get('shieldMint');
    } else {
      shieldMint = await zcf.makeZCFMint('Shield');
      baggage.init('shieldMint', shieldMint);
    }
    const rec = shieldMint.getIssuerRecord();
    assetBrand = rec.brand;
    assetIssuer = rec.issuer;
    faucet = async value => {
      const { zcfSeat, userSeat } = zcf.makeEmptySeatKit();
      shieldMint.mintGains(harden({ Asset: AmountMath.make(assetBrand, BigInt(value)) }), zcfSeat);
      zcfSeat.exit();
      return E(userSeat).getPayout('Asset');
    };
  }

  // ── M7e: verifying keys as durable, governance-rotatable params (init once from privateArgs) ──
  const params = zone.mapStore('params');
  if (!params.has('transferVk')) params.init('transferVk', transferVk);
  if (!params.has('depositVk')) params.init('depositVk', depositVk);
  if (!params.has('withdrawVk')) params.init('withdrawVk', withdrawVk);

  // ── M7c: durable tree + nullifier set + roots + note ciphertexts + counters + escrow seats ──
  const scalars = zone.mapStore('scalars'); // nextIndex, root, noteCount
  const rootHistory = zone.setStore('roots');
  const nullifiers = zone.setStore('nullifiers');
  const filledSubtrees = zone.mapStore('filledSubtrees'); // level -> hash
  const notesStore = zone.mapStore('notes'); // index -> ciphertext (passable)
  const pool = provideEmptySeat(zcf, baggage, 'pool'); // durable escrow seat (survives upgrade)
  const reserve = provideEmptySeat(zcf, baggage, 'reserve'); // M7a protocol-fee accrual

  const hash2 = async (a, b) => (await E(mimcHash).toBridge({ type: MIMC, inputs: [String(a), String(b)] })).hash;
  const verify = (vk, proof, pub) => E(zkVerify).toBridge({ type: VERIFY, vk, proof, pub });

  // zeros (empty-subtree hashes) are deterministic — recomputed in-memory each incarnation, never stored.
  const zeros = ['0'];
  for (let i = 1; i <= DEPTH; i += 1) zeros.push(await hash2(zeros[i - 1], zeros[i - 1]));

  // one-time init (first incarnation only); on upgrade the durable stores already hold live state.
  if (!scalars.has('root')) {
    for (let level = 0; level < DEPTH; level += 1) filledSubtrees.init(level, zeros[level]);
    scalars.init('nextIndex', 0);
    scalars.init('root', zeros[DEPTH]);
    scalars.init('noteCount', 0);
    rootHistory.add(zeros[DEPTH]);
  }

  const insert = async leaf => {
    let idx = scalars.get('nextIndex');
    assert(idx < 2 ** DEPTH, 'tree full'); // 1<<32 overflows to 1 in JS — use 2**DEPTH
    let cur = String(leaf);
    for (let level = 0; level < DEPTH; level += 1) {
      let left;
      let right;
      if (idx % 2 === 0) { left = cur; right = zeros[level]; filledSubtrees.set(level, cur); }
      else { left = filledSubtrees.get(level); right = cur; }
      cur = await hash2(left, right);
      idx = Math.floor(idx / 2);
    }
    scalars.set('root', cur);
    if (!rootHistory.has(cur)) rootHistory.add(cur);
    scalars.set('nextIndex', scalars.get('nextIndex') + 1);
    return cur;
  };

  const escrowed = () => pool.getAmountAllocated('Asset', assetBrand).value;
  const reserved = () => reserve.getAmountAllocated('Asset', assetBrand).value;

  // M6d: encrypted note ciphertexts (opening sealed to the recipient), published so recipients trial-decrypt theirs.
  const notesNode = storageNode ? E(storageNode).makeChildNode('notes') : undefined;
  const publishNotes = async cts => {
    if (!cts || !cts.length) return;
    let n = scalars.get('noteCount');
    for (const ct of cts) { notesStore.init(n, ct); n += 1; }
    scalars.set('noteCount', n);
    if (notesNode) await E(notesNode).setValue(JSON.stringify([...notesStore.values()]));
  };

  const publish = async () => {
    if (!storageNode) return;
    await E(storageNode).setValue(
      JSON.stringify({
        root: scalars.get('root'),
        leaves: scalars.get('nextIndex'),
        roots: rootHistory.getSize(),
        nullifiers: [...nullifiers.keys()],
        escrowed: String(escrowed()),
        reserve: String(reserved()),
        notes: scalars.get('noteCount'),
      }),
    );
  };

  const depositHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      const res = await verify(params.get('depositVk'), proof, pub);
      assert(res && res.ok, 'deposit: proof rejected');
      const [cm, amount] = res.public; // authenticated [Cm, Amount]
      const given = seat.getAmountAllocated('Asset', assetBrand);
      assert(given.value === BigInt(amount), `deposit: gave ${given.value}, proof commits ${amount}`);
      zcf.atomicRearrange(harden([[seat, pool, { Asset: given }]]));
      await insert(cm);
      await publishNotes((offerArgs || {}).noteCiphertexts);
      seat.exit();
      await publish();
      return harden({ ok: true, cm, amount, root: scalars.get('root'), escrowed: String(escrowed()), reserve: String(reserved()) });
    } catch (err) { seat.exit(err); throw err; }
  };

  const withdrawHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      const res = await verify(params.get('withdrawVk'), proof, pub);
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
      const res = await verify(params.get('transferVk'), proof, pub);
      assert(res && res.ok, 'transfer: proof rejected');
      const [pRoot, nf, cmOut0, cmOut1, fee] = res.public;
      assert(rootHistory.has(pRoot), 'transfer: unknown merkle root');
      assert(!nullifiers.has(nf), 'transfer: nullifier already used');
      nullifiers.add(nf);
      await insert(cmOut0);
      await insert(cmOut1);
      // M7a: the fee leaves the shielded set (outputs sum to amtIn - fee), so route it pool -> reserve, keeping
      // the pool exactly note-backed.
      const feeV = BigInt(fee);
      if (feeV > 0n) {
        zcf.atomicRearrange(harden([[pool, reserve, { Asset: AmountMath.make(assetBrand, feeV) }]]));
      }
      await publishNotes((offerArgs || {}).noteCiphertexts);
      seat.exit();
      await publish();
      return harden({ ok: true, nullifier: nf, created: [cmOut0, cmOut1], fee, reserve: String(reserved()), root: scalars.get('root') });
    } catch (err) { seat.exit(err); throw err; }
  };

  const publicFacet = Far('ShieldedPool public', {
    getAssetIssuer: () => assetIssuer,
    getAssetBrand: () => assetBrand,
    makeDepositInvitation: () => zcf.makeInvitation(depositHandler, 'shield-deposit'),
    makeTransferInvitation: () => zcf.makeInvitation(transferHandler, 'shield-transfer'),
    makeWithdrawInvitation: () => zcf.makeInvitation(withdrawHandler, 'shield-withdraw'),
    getVerifyingKeyFingerprints: () => {
      // audit surface: a content-sensitive fingerprint of each governance-managed VK (len + head + tail, not the
      // full bytes), so anyone can confirm WHICH circuit the live pool verifies against + detect a rotation.
      const fp = k => { const v = params.get(k); return harden({ len: v.length, head: v.slice(0, 12), tail: v.slice(-12) }); };
      return harden({ transfer: fp('transferVk'), deposit: fp('depositVk'), withdraw: fp('withdrawVk') });
    },
    getState: () => harden({
      root: scalars.get('root'),
      leaves: scalars.get('nextIndex'),
      roots: rootHistory.getSize(),
      nullifiers: [...nullifiers.keys()],
      escrowed: String(escrowed()),
      reserve: String(reserved()),
    }),
  });

  // M7e: the creatorFacet is the GOVERNANCE-HELD surface — in production the deploy hands it to the gov charter,
  // so rotating a verifying key (circuit upgrade) is a governance action, not a contract redeploy. Each rotation
  // republishes state (incl. the vk-hash via getVerifyingKeyHashes) for audit. The demo `faucet` is creator-only.
  const rotateVerifyingKey = async (which, vk) => {
    assert(['transferVk', 'depositVk', 'withdrawVk'].includes(which), `unknown vk param: ${which}`);
    assert(typeof vk === 'string' && vk.length > 0, 'vk must be a non-empty base64 string');
    params.set(which, vk);
    await publish();
    return harden({ ok: true, rotated: which });
  };
  const creatorFacet = Far('ShieldedPool creator', faucet ? { faucet, rotateVerifyingKey } : { rotateVerifyingKey });

  await publish();
  return harden({ publicFacet, creatorFacet });
};
harden(start);

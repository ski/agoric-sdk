// @ts-nocheck
// ADR 0014 shielded pool with REAL value escrow (deposit / transfer / withdraw).
//
//   - deposit: give N Asset (proposal give {Asset}) + a deposit proof binding cm to N -> escrow + insert cm.
//   - transfer: confidential 1-in/2-out (M6a/M6b) -> no value moves, only the commitment set changes.
//   - withdraw: a withdraw proof for a revealed amount + want {Asset: N} -> pay N from the pool, burn (nf).
//
// M7c — DURABLE + UPGRADABLE. The 3rd `baggage` arg makes Zoe treat this as upgradable; ALL state (tree, roots,
//   nullifiers, note ciphertexts, counters, the escrow + reserve seats) lives in baggage-backed durable stores,
//   AND the public/creator facets are durable EXOS (zone.exoClassKit) so the vat actually revives across an
//   upgrade (plain Far facets fail startVat on the next incarnation). State + identity both survive.
// M7e — verifying keys are DURABLE, GOVERNANCE-ROTATABLE params (not deploy-baked): a durable `params` store,
//   init once from privateArgs, rotated via the creatorFacet (the gov-held facet) — no redeploy — with a
//   content fingerprint published for audit.
//
// Value-layer is asset-agnostic. PRODUCTION starts with issuerKeywordRecord { Asset: IST }; self-minted "Shield"
// is the demo fallback. Root on-chain (M6b); nullifiers prevent double-spend (M4); owner-bound notes (M6a); depth 32 (M7b).
//
// privateArgs: { zkVerify, mimcHash, transferVk, depositVk, withdrawVk, storageNode? }
import { E } from '@endo/far';
import { AmountMath } from '@agoric/ertp';
import { M, provide } from '@agoric/vat-data';
import { makeDurableZone } from '@agoric/zone/durable.js';
import { provideEmptySeat } from '@agoric/zoe/src/contractSupport/durability.js';

const VERIFY = 'VERIFY_GROTH16_BN254';
const MIMC = 'MIMC_BN254';
const DEPTH = 32; // M7b production depth — MUST match the circuit (pool.TreeDepth) or proof roots never line up

export const start = async (zcf, privateArgs, baggage) => {
  const { zkVerify, mimcHash, transferVk, depositVk, withdrawVk, storageNode } = privateArgs;
  assert(zkVerify && mimcHash, 'zkVerify + mimcHash required');
  const zone = makeDurableZone(baggage);

  // ── asset: IST in production (terms.Asset), self-minted Shield in the demo (durable mint, reused on upgrade) ──
  const terms = zcf.getTerms();
  let assetBrand;
  let assetIssuer;
  let mintFaucet; // demo only — returns a Shield payment; undefined in IST mode
  if (terms.brands && terms.brands.Asset) {
    assetBrand = terms.brands.Asset;
    assetIssuer = terms.issuers.Asset;
  } else {
    let shieldMint;
    if (baggage.has('shieldMint')) shieldMint = baggage.get('shieldMint');
    else { shieldMint = await zcf.makeZCFMint('Shield'); baggage.init('shieldMint', shieldMint); }
    const rec = shieldMint.getIssuerRecord();
    assetBrand = rec.brand;
    assetIssuer = rec.issuer;
    mintFaucet = async value => {
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

  const firstIncarnation = !scalars.has('root'); // true only on initial deploy; false on every upgrade

  // zeros (empty-subtree hashes) are deterministic. CRITICAL for upgrade: compute them via the mimcHash BRIDGE
  // only on the FIRST incarnation (cross-vat calls are allowed then) and persist them; an UPGRADE incarnation must
  // finish buildRootObject WITHOUT contacting other vats, so it just reads them back from the durable store.
  const zerosStore = zone.mapStore('zeros');
  if (!zerosStore.has(0)) {
    let z = '0';
    zerosStore.init(0, z);
    for (let i = 1; i <= DEPTH; i += 1) { z = await hash2(z, z); zerosStore.init(i, z); }
  }
  const zeros = [];
  for (let i = 0; i <= DEPTH; i += 1) zeros.push(zerosStore.get(i)); // in-memory mirror (sync read; no bridge on upgrade)

  // one-time init + initial publish (first incarnation only); on upgrade the durable stores already hold live state
  // and we must NOT call the bridge/vstorage here (buildRootObject would never resolve).
  if (firstIncarnation) {
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

  const notesNode = storageNode ? E(storageNode).makeChildNode('notes') : undefined;
  const publishNotes = async cts => {
    if (!cts || !cts.length) return;
    let n = scalars.get('noteCount');
    for (const ct of cts) { notesStore.init(n, ct); n += 1; }
    scalars.set('noteCount', n);
    if (notesNode) await E(notesNode).setValue(JSON.stringify([...notesStore.values()]));
  };

  const stateView = () => harden({
    root: scalars.get('root'),
    leaves: scalars.get('nextIndex'),
    roots: rootHistory.getSize(),
    nullifiers: [...nullifiers.keys()],
    escrowed: String(escrowed()),
    reserve: String(reserved()),
  });
  const publish = async () => {
    if (!storageNode) return;
    await E(storageNode).setValue(JSON.stringify({ ...stateView(), notes: scalars.get('noteCount') }));
  };

  const depositHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      const res = await verify(params.get('depositVk'), proof, pub);
      assert(res && res.ok, 'deposit: proof rejected');
      const [cm, amount] = res.public;
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
      const [pRoot, nf, amount] = res.public;
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
      const feeV = BigInt(fee);
      if (feeV > 0n) zcf.atomicRearrange(harden([[pool, reserve, { Asset: AmountMath.make(assetBrand, feeV) }]]));
      await publishNotes((offerArgs || {}).noteCiphertexts);
      seat.exit();
      await publish();
      return harden({ ok: true, nullifier: nf, created: [cmOut0, cmOut1], fee, reserve: String(reserved()), root: scalars.get('root') });
    } catch (err) { seat.exit(err); throw err; }
  };

  const fingerprint = k => { const v = params.get(k); return harden({ len: v.length, head: v.slice(0, 12), tail: v.slice(-12) }); };

  // ── durable EXO facets (M7c): identity persists across upgrade; behavior is re-bound to this incarnation's
  // closures (durable stores + re-supplied bridge presences) each time start() runs. loose guards (passable). ──
  const anyGuard = M.interface('ShieldedPool', {}, { defaultGuards: 'passable' });
  const makeKit = zone.exoClassKit('ShieldedPool', { publicFacet: anyGuard, creatorFacet: anyGuard }, () => ({}), {
    publicFacet: {
      getAssetIssuer() { return assetIssuer; },
      getAssetBrand() { return assetBrand; },
      makeDepositInvitation() { return zcf.makeInvitation(depositHandler, 'shield-deposit'); },
      makeTransferInvitation() { return zcf.makeInvitation(transferHandler, 'shield-transfer'); },
      makeWithdrawInvitation() { return zcf.makeInvitation(withdrawHandler, 'shield-withdraw'); },
      // audit surface: content fingerprint of each governance-managed VK (len + head + tail), not the bytes.
      getVerifyingKeyFingerprints() { return harden({ transfer: fingerprint('transferVk'), deposit: fingerprint('depositVk'), withdraw: fingerprint('withdrawVk') }); },
      getState() { return stateView(); },
    },
    creatorFacet: {
      // demo only — throws in IST mode (nothing to mint).
      async faucet(value) { assert(mintFaucet, 'no faucet: IST-escrow mode'); return mintFaucet(value); },
      // M7e: rotate a verifying key (circuit upgrade) WITHOUT a redeploy. In production this facet is held by the
      // governance charter, so a rotation is a governance action; the new fingerprint is republished for audit.
      async rotateVerifyingKey(which, vk) {
        assert(['transferVk', 'depositVk', 'withdrawVk'].includes(which), `unknown vk param: ${which}`);
        assert(typeof vk === 'string' && vk.length > 0, 'vk must be a non-empty base64 string');
        params.set(which, vk);
        await publish();
        return harden({ ok: true, rotated: which });
      },
    },
  });

  // create once, durably; on upgrade `provide` returns the same exo (re-bound to the new behavior above).
  const { publicFacet, creatorFacet } = provide(baggage, 'thePool', () => makeKit());
  if (firstIncarnation) await publish(); // bridge/vstorage call is allowed only on the first incarnation
  return harden({ publicFacet, creatorFacet });
};
harden(start);

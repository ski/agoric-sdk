// ADR 0014 #1 spike — confidential payout: a PAYER (borrower income / the protocol) routes value to a RECIPIENT
// (e.g. a lender) THROUGH the shielded pool, as a note owned by the recipient. The recipient retrieves it
// (withdraw), unlinkable to the payout — so the cashflow no longer betrays the relationship (the lending leak
// ADR 0014 set out to close). This is the integration pattern every moimoi value flow (lending payout, buy/sell
// proceeds, royalty split, paid follow) would use; here it's proven end-to-end on the fork chain.
//   node gen-payout-coreeval.mjs <BUNDLE_ID>
import { readFileSync, writeFileSync } from 'node:fs';
const BUNDLE_ID = process.argv[2];
if (!BUNDLE_ID || !BUNDLE_ID.startsWith('b1-')) throw new Error('usage: node gen-payout-coreeval.mjs <b1-bundleId>');
const dep = JSON.parse(readFileSync(new URL('./payout-deposit.json', import.meta.url), 'utf8'));
const wd = JSON.parse(readFileSync(new URL('./payout-withdraw.json', import.meta.url), 'utf8'));
const vk = n => readFileSync(new URL(`./setup-assets/${n}-vk.b64`, import.meta.url), 'utf8').trim();

const ce = `/* global E, harden */
/// <reference types="@agoric/vats/src/core/core-eval-env"/>
const BUNDLE_ID = ${JSON.stringify(BUNDLE_ID)};
const TVK = ${JSON.stringify(vk('transfer'))};
const DVK = ${JSON.stringify(vk('deposit'))};
const WVK = ${JSON.stringify(vk('withdraw'))};
const DEP_PROOF = ${JSON.stringify(dep.proof)}; const DEP_PUB = ${JSON.stringify(dep.pub)};
const WD_PROOF = ${JSON.stringify(wd.proof)}; const WD_PUB = ${JSON.stringify(wd.pub)};

const run = async powers => {
  const { consume: { bridgeManager, zoe, chainStorage } } = powers;
  const bm = await bridgeManager;
  const zkVerify = await E(bm).register('zkVerify');
  const mimcHash = await E(bm).register('mimcHash');
  const storageNode = await E(chainStorage).makeChildNode('shieldedPayout');
  const pa = harden({ zkVerify, mimcHash, transferVk: TVK, depositVk: DVK, withdrawVk: WVK, storageNode });
  const installation = await E(zoe).installBundleID(BUNDLE_ID);
  const { publicFacet, creatorFacet } = await E(zoe).startInstance(installation, harden({}), harden({}), pa);
  const brand = await E(publicFacet).getAssetBrand();
  const issuer = await E(publicFacet).getAssetIssuer();
  const amt = v => harden({ brand, value: v });

  // PAYER funds the payout (demo faucet stands in for borrower income / protocol proceeds) and deposits a note
  // OWNED BY THE RECIPIENT (nk = recipient's), with the opening sealed to the recipient in noteCiphertexts.
  const pmt = await E(creatorFacet).faucet(1000);
  const depSeat = await E(zoe).offer(
    await E(publicFacet).makeDepositInvitation(),
    harden({ give: { Asset: amt(1000n) } }), harden({ Asset: pmt }),
    harden({ proof: DEP_PROOF, pub: DEP_PUB, noteCiphertexts: [{ sealedTo: 'recipient-encPub', opening: 'aead-box' }] }));
  const payout = await E(depSeat).getOfferResult().then(() => ({ ok: true })).catch(e => ({ ok: false, e: String(e.message || e) }));
  const escrowedAfterPayout = (await E(publicFacet).getState()).escrowed;

  // RECIPIENT retrieves the note (withdraw) — unlinkable to the payout; lender gets paid without the loan->lender link.
  const wSeat = await E(zoe).offer(
    await E(publicFacet).makeWithdrawInvitation(),
    harden({ want: { Asset: amt(1000n) } }), harden({}),
    harden({ proof: WD_PROOF, pub: WD_PUB }));
  const withdraw = await E(wSeat).getOfferResult()
    .then(async () => { const p = await E(wSeat).getPayout('Asset'); const got = await E(issuer).getAmountOf(p); return { ok: true, paidOut: String(got.value) }; })
    .catch(e => ({ ok: false, e: String(e.message || e) }));

  // replay the same withdraw -> must be rejected by the nullifier (no double-spend).
  const wSeat2 = await E(zoe).offer(
    await E(publicFacet).makeWithdrawInvitation(),
    harden({ want: { Asset: amt(1000n) } }), harden({}),
    harden({ proof: WD_PROOF, pub: WD_PUB }));
  const replay = await E(wSeat2).getOfferResult().then(() => ({ rejected: false })).catch(e => ({ rejected: true, e: String(e.message || e) }));

  const finalEscrow = (await E(publicFacet).getState()).escrowed;
  await E(storageNode).setValue(JSON.stringify({ payout, escrowedAfterPayout, withdraw, replay, finalEscrow }));
};
run;
`;
writeFileSync(new URL('./payout-coreeval.js', import.meta.url), ce);
writeFileSync(new URL('./payout-permit.json', import.meta.url), JSON.stringify({ consume: { bridgeManager: true, zoe: true, chainStorage: true } }) + '\n');
console.log('wrote payout-coreeval.js + payout-permit.json (bundle', BUNDLE_ID.slice(0, 12) + '…)');

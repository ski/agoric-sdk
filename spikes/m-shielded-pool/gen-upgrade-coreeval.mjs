// ADR 0014 M7c/M7e live test generator: a core-eval that deploys the durable pool, deposits (durable state),
// rotates a VK (M7e), UPGRADES the contract to the same bundle, then reads state via a FRESH publicFacet to
// prove the baggage-backed tree/nullifiers/escrow SURVIVED the upgrade (M7c).
//   node gen-upgrade-coreeval.mjs <BUNDLE_ID>
import { readFileSync, writeFileSync } from 'node:fs';
const BUNDLE_ID = process.argv[2];
if (!BUNDLE_ID || !BUNDLE_ID.startsWith('b1-')) throw new Error('usage: node gen-upgrade-coreeval.mjs <b1-bundleId>');
const dep = JSON.parse(readFileSync(new URL('./dep-proof.json', import.meta.url), 'utf8'));
const vk = n => readFileSync(new URL(`./setup-assets/${n}-vk.b64`, import.meta.url), 'utf8').trim();

const ce = `/* global E, harden */
/// <reference types="@agoric/vats/src/core/core-eval-env"/>
const BUNDLE_ID = ${JSON.stringify(BUNDLE_ID)};
const TVK = ${JSON.stringify(vk('transfer'))};
const DVK = ${JSON.stringify(vk('deposit'))};
const WVK = ${JSON.stringify(vk('withdraw'))};
const DEP_PROOF = ${JSON.stringify(dep.proof)};
const DEP_PUB = ${JSON.stringify(dep.pub)};
const AMT = ${dep.amount}n;

const run = async powers => {
  const { consume: { bridgeManager, zoe, chainStorage } } = powers;
  const bm = await bridgeManager;
  const zkVerify = await E(bm).register('zkVerify');
  const mimcHash = await E(bm).register('mimcHash');
  const storageNode = await E(chainStorage).makeChildNode('shieldedUpgradeTest');
  const pa = harden({ zkVerify, mimcHash, transferVk: TVK, depositVk: DVK, withdrawVk: WVK, storageNode });

  const installation = await E(zoe).installBundleID(BUNDLE_ID);
  const kit = await E(zoe).startInstance(installation, harden({}), harden({}), pa); // demo Shield asset
  const { publicFacet, creatorFacet, adminFacet, instance } = kit;
  const brand = await E(publicFacet).getAssetBrand();

  // deposit → durable state (leaves:1, escrowed:1000)
  const pmt = await E(creatorFacet).faucet(Number(AMT));
  const inv = await E(publicFacet).makeDepositInvitation();
  const seat = await E(zoe).offer(inv,
    harden({ give: { Asset: { brand, value: AMT } } }),
    harden({ Asset: pmt }),
    harden({ proof: DEP_PROOF, pub: DEP_PUB, noteCiphertexts: [{ n: 'upgrade-test' }] }));
  const deposit = await E(seat).getOfferResult().then(() => ({ ok: true })).catch(e => ({ ok: false, e: String(e.message || e) }));
  const before = await E(publicFacet).getState();

  // M7e: rotate a VK via the (gov-held) creatorFacet + audit fingerprint before/after
  const fpBefore = await E(publicFacet).getVerifyingKeyFingerprints();
  const rotate = await E(creatorFacet).rotateVerifyingKey('withdrawVk', 'ROTATED_TEST_VK_BASE64==').then(r => r).catch(e => ({ ok: false, e: String(e.message || e) }));
  const fpAfter = await E(publicFacet).getVerifyingKeyFingerprints();

  // M7c: UPGRADE to the same bundle, then read state via a FRESH publicFacet (the captured Far one is stale post-upgrade)
  const upgrade = await E(adminFacet).upgradeContract(BUNDLE_ID, pa).then(() => ({ ok: true })).catch(e => ({ ok: false, e: String(e.message || e) }));
  const pf2 = await E(zoe).getPublicFacet(instance);
  const after = await E(pf2).getState();
  const fpAfterUpgrade = await E(pf2).getVerifyingKeyFingerprints();

  await E(storageNode).setValue(JSON.stringify({
    deposit, before, rotate, fpBefore, fpAfter, upgrade, after, fpAfterUpgrade,
    survived: before.leaves === after.leaves && before.escrowed === after.escrowed && before.root === after.root,
  }));
};
run;
`;
writeFileSync(new URL('./upgrade-coreeval.js', import.meta.url), ce);
writeFileSync(new URL('./upgrade-permit.json', import.meta.url),
  JSON.stringify({ consume: { bridgeManager: true, zoe: true, chainStorage: true } }) + '\n');
console.log('wrote upgrade-coreeval.js + upgrade-permit.json (bundle', BUNDLE_ID.slice(0, 12) + '…)');

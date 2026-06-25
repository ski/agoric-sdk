#! false node --ignore-this-line
/* global E */
/// <reference types="@agoric/vats/src/core/core-eval-env"/>

// ADR 0014 M6c live proof: real value escrow round-trip.
//   faucet 1000 Asset -> deposit (give 1000 + deposit proof binding cm<->1000) -> escrowed 1000
//   -> withdraw (withdraw proof for 1000 + want 1000) -> paid out, escrowed 0
//   -> withdraw again (replay) -> rejected (nullifier).
// Conservation: value in == value out; the nullifier prevents double-withdraw. Asset is a self-contained demo
// token (production: IST) — the deposit/withdraw/escrow code path is identical.

const BUNDLE_ID = 'b1-106c2f578b9412bb39a98d15d4d09cfc56f6aedb6564870f74336c2c50089a044e97f976bc7ef5be6536d5adb9ae85d33f1d75003bc55ab90e865ca43e11fcc9';

const TRANSFER_VK =
  'xSAx5cMJDu7AySHBUFkAt5ly8S22ZKNxTz5bDVHg0RWO/BtF+qTBxng3E/1zZ+WZPGWfo+2RywHttIGSenvOYYN6xHn0xgSE6OEjqTKE6DbAZEDVhDQgkgCg5hLCqziRJ5J4duHSDYEJXv1xcNG7g4FaBDo8/G0g5tvH1NJD10qZjpOTkg1IOnJgv7cx+10l8apJMzWp5xKX5IW3rvMSwhgA3u8SHx52QmoAZl5cRHlnQyLU917a3UbevVzZkvbt5yKSeBxlPwQyFitc0tOfoXNvTOYTyo0nI6GM185SL4rTHDyoHRBOe/ZoF8oA2FucKkF4AQjDpU2wrL3Z7bCkWRs9oLBIiouP8JLQeSURntibabtacwzt9WJ/plHyxZvbAAAABupGoenpG0oQhvy94ZZg/bOqHqpS5DFbwylICSjrWDRyrvoHC+2rXVKZ1jBWlinsQJSDt9bIhABN6tEdK0RNQZWS9AeYzxaDRtOqu4ogopertX1XxnDCHPS8iQAvVs+VadQ9RR1GXIzTHipgFYqqVic1kAEINhMiXilf0N7UOJbFxp4uThhtMY+SownpoZLTzPppt2G3P4ZQo7HNnag69naRuK0c6FyhfedxuWeY0K6SV1Jh3Jp9hgfh1xZjt9uqaAAAAAAAAAAA';
const DEPOSIT_VK =
  'p2KoBLr5O2ZTCKoJzs0V6GjhVbw3eJDovrUR8Co6yE7r2Jju4voZM7+s95fR3QuXdg5PCaRrXVtj7YDOg3BjJay5gQxOROutidE3PUE/Kg3psxBz1ZJGGwD+9nWS3mnxA92MRhgJmRogXZU5HgATcbqjrFQ1xQ6foBZ5ifB8fO7q/qsby1iEqOXUkGl8dxDOHOWpdwUOPf2267NuZu3tAy0z1/A7yNikAri426f9xwmpkOeP7bFmUTvgEl/F1IpR7eT054tOJOaR4TiVh9eSRWs8rVsI2XZjYy3DWMm3VPGYBWc6H/2kNv60TGF9W3vWkq0grsk9pBmXRBodtM994QY6smLimMy0X7Bt8JNxwYHzjooFsGoodJN+ttvCAheiAAAAA4EL2+5v4/cMbmuK5QexbQYwUgbA/LHvTyBOhpnDucIQsA/eWj8NbUxXulCxWm7n+ob2CFDoyPUHRA+Z/KlUXjOIVVD6meC3d2RZmkOK6jtQqsiTj2IHRug5F4RLC6v6bwAAAAAAAAAA';
const WITHDRAW_VK =
  '5zkYQKrFhFegKd+FeJq4LObIYAYQlxTgMF8g/HAA/byRdI+eM/UsHDdvaj6g0gQie/MZJ7RE9aZLvhZr1++/7NAOl/BNONaBofyvWHn63XhvaeACF9PINsq2nqGOYjqADQi3ReQT6ekCODzvLyNdYFu/U6k/cYMSFle9Eg7xUvStwrvd470GvKG5Y9FXuWtr34Lx4+W1UhBQEYot4/ptBQ+ci47VVBgV0lc5SIDP29WpZfmP8daVGpAPB/wIc3GCpG78zp0q9bHBt/JVUDPn7u9GQl9P4ZItCENEEkCy+IOUgJt/AiFMucg/g1TsKsDRQbymE9oype1t0a+ls114uQWEcgeBgmkdrILFt8hkvUT0rDqcp8JqEi86B3rp9kOFAAAABOkGkxQWIMSYWaUPZ1jNExvJ0NoFQeTz+oZ10o9xWB2xjRaCkJ1vcWRxIezIcMUcGLer+x9HRydXSoTk+y7o3QTn6R5w5rzbGpeXGMC9cXD3KQoFyPnjOsTXHl1zyeEDBZSr0REFIWd49roS26Uk9+6QdDVW2jA6jzINjUsWwA9rAAAAAAAAAAA=';

const DEP_PROOF =
  'yyOILQqMuLFKpB1M1hcakrSWD4JcswYHfxV8oc839LLgt8sUWWLVWQyMtEd+ZojH6iAcq+NaVUUuHPLsBnVV8wBK2lzIQ1ChxceUnfItEgRNDWBoANbzA6pe93qfbks6gi62T4yKlrJCLXHHEulenFsih11d1Lci96KCu7BD+Z8AAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const DEP_PUB =
  'AAAAAgAAAAAAAAACFLLB2ALuI6AXMrHBUKmgfSuo5BiE5E30ly95Xg+DYq8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD6A==';
const WD_PROOF =
  'ksK99KeMxBsEirhQgXD+NYz8VsmWQG0HvRdO4XxhFSGsFK0nC94iTT6fn/DAH/F1lXF0ecWdtJ1OYMkCzHmFFiu11M/6+P3+4pSKEopNgv+EYmDZmIhLHs+sZtLOYjLErCLwyasgXt19f/giQ7qw6kLVc69czxBtf09lqRfXISYAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const WD_PUB =
  'AAAAAwAAAAAAAAADDtUJ8apMrSyk+weAac6K/2HofhXYli/oPaaTWeSeNo4WomwFdZk7uUrlJy0QufuS1fFOtwwRIQ2iM8+vbfL8EgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPo';

const run = async powers => {
  const {
    consume: { bridgeManager, zoe, chainStorage },
  } = powers;

  const bm = await bridgeManager;
  const zkVerify = await E(bm).register('zkVerify');
  const mimcHash = await E(bm).register('mimcHash');
  const storageNode = await E(chainStorage).makeChildNode('shieldedEscrow');
  const testNode = await E(chainStorage).makeChildNode('shieldedEscrowTest');

  const installation = await E(zoe).installBundleID(BUNDLE_ID);
  const { publicFacet, creatorFacet } = await E(zoe).startInstance(
    installation,
    harden({}),
    harden({}),
    harden({ zkVerify, mimcHash, transferVk: TRANSFER_VK, depositVk: DEPOSIT_VK, withdrawVk: WITHDRAW_VK, storageNode }),
  );

  const brand = await E(publicFacet).getAssetBrand();
  const issuer = await E(publicFacet).getAssetIssuer();
  const amt = n => harden({ brand, value: BigInt(n) });

  // fund a depositor with 1000 Asset
  const payment = await E(creatorFacet).faucet(1000);

  // deposit: give 1000 + deposit proof
  const depInv = await E(publicFacet).makeDepositInvitation();
  const depSeat = await E(zoe).offer(depInv, harden({ give: { Asset: amt(1000) } }), harden({ Asset: payment }), harden({ proof: DEP_PROOF, pub: DEP_PUB }));
  const deposit = await E(depSeat).getOfferResult().then(r => ({ ok: true, r })).catch(e => ({ ok: false, e: String(e.message || e) }));

  // withdraw: want 1000 + withdraw proof
  const doWithdraw = async label => {
    const inv = await E(publicFacet).makeWithdrawInvitation();
    const seat = await E(zoe).offer(inv, harden({ want: { Asset: amt(1000) } }), harden({}), harden({ proof: WD_PROOF, pub: WD_PUB }));
    try {
      const r = await E(seat).getOfferResult();
      const pmt = await E(seat).getPayout('Asset');
      const got = await E(issuer).getAmountOf(pmt);
      return { label, ok: true, r, paidOut: String(got.value) };
    } catch (e) {
      return { label, ok: false, e: String(e.message || e) };
    }
  };

  const withdraw = await doWithdraw('withdraw');
  const replay = await doWithdraw('double-withdraw');

  const finalState = await E(publicFacet).getState();
  await E(testNode).setValue(JSON.stringify({ deposit, withdraw, replay, finalState }));
};

run;

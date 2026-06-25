#! false node --ignore-this-line
/* global E */
/// <reference types="@agoric/vats/src/core/core-eval-env"/>

// ADR 0014 M3 live proof: install + start the confidential-transfer contract, seed the input note, then run
// three transfers — a real proof (accepted), a tampered proof (rejected), and a replay of the real proof
// (double-spend rejected by the nullifier set). Outcomes + final ledger are written to vstorage.

const BUNDLE_ID =
  "b1-4d535fbb12a2d2bdc59a81cc24acb7efb5c2c04b7fbe5bd17d2d63e934476fd56652c3c948e357e836cbf1aebc7af08ef9901a08938d5578d362f12ab4a178eb";

// the input note commitment (CommIn = MiMC(1000,11111)), authenticated public[0] of the spike-i proof
const CIN =
  "11342481785277919936393333618222177573277740489867558530293867733261336889108";

const VK =
  "o9NRMsXElrd/HyA5Kd5bNMOTX/0uO/jp/PHtAxyOkgyAcZbitMjaFWExK+8EGxJxWANJaddx2Xn54Gf5fHxc0YoX7PxIz6EvmzmaDcvOdVbKombkaSppMLUn7loKIZd1FvMlXZ+C/eOZ2lupQbEgE+zKIzdm7IKaPgPqZ3r2+NapBcZ6rA5YkEO/Y5AwU8ujQDRZ2FutnNJqS/UMwziMFxb46KiS5lgLEXHVdhpNnlejQ+ZgFp9kgMAs7vdVdFtNyPslLJg3VMkf4BhZG2Q2KjlKqd8D4ujAUOfWHvuDFP2WnIcJwgE+BsSIYclJ2XToo+PmB6Up5kWW9a+fdXhrahMAlYtpwiodZo8vrE6Q6q02sT6fWkTh4pHQNd62HchlAAAABcVwffPd+WMVmrkkI9H3ptETm/4q3HN2Q0hivymlLoE/2udOkEVXkgKy42/xMc4ICVKiJIj4eu5t6C7W/44neZ3G1s+5tJbmBrzHF8M2VJVptVbjhXeOSUQP4yCUsWPpMJGFzN+fPeNvKga8mirRZr+PtyHPGrpVTOUpcuwjKc/whhpX5aB7Kzp8m1EPsPVcg+R+ivz+rgUix7XTAOP7ig8AAAAAAAAAAA==";
const PROOF =
  "gb3QXra6eZraYJDlIrGY0dqPXu5LI2e2lETJAxFA2kaMaOD6dWIkNcYjlUYewt5UiNmyI+BuboIAwQJ/ODDCsCmB/SyWfo2wPjl1J5/okXfeLgndl4fExMtgK+v85oNupvDBb/po42xXqweX2nQhkbimUyHLrortAKllzjNyGQkAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PUB =
  "AAAABAAAAAAAAAAEGROeAAUnLVu4IN42AIz8S7q/79n0SOsS+DVkeiR6xxQPGOmRidjBk6t6XlxcXnVGic5GIjHbO7znW1otHoo8dAgNVPjTYTj8ecVyE8prfrcyhXGbmFrT+NC3g2VkWFBPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=";

const run = async powers => {
  const {
    consume: { bridgeManager, zoe, chainStorage },
  } = powers;

  const bm = await bridgeManager;
  const zkVerify = await E(bm).register("zkVerify");

  const storageNode = await E(chainStorage).makeChildNode("confidentialTransfer");
  const testNode = await E(chainStorage).makeChildNode("confidentialTransferTest");

  const installation = await E(zoe).installBundleID(BUNDLE_ID);
  const { publicFacet, creatorFacet } = await E(zoe).startInstance(
    installation,
    harden({}),
    harden({}),
    harden({ zkVerify, vk: VK, storageNode }),
  );

  await E(creatorFacet).seedNote(CIN);

  const doTransfer = async (proof, pub, label) => {
    const inv = await E(publicFacet).makeTransferInvitation();
    const seat = await E(zoe).offer(inv, harden({}), harden({}), harden({ proof, pub }));
    try {
      const result = await E(seat).getOfferResult();
      return { label, accepted: true, result };
    } catch (err) {
      return { label, accepted: false, error: String((err && err.message) || err) };
    }
  };

  const good = await doTransfer(PROOF, PUB, "valid");

  // tamper one base64 char (stays valid base64, corrupts the proof bytes → must fail closed)
  const i = 12;
  const badProof = PROOF.slice(0, i) + (PROOF[i] === "A" ? "B" : "A") + PROOF.slice(i + 1);
  const tampered = await doTransfer(badProof, PUB, "tampered");

  // replay the valid proof: CIN is now nullified → double-spend must be rejected
  const replay = await doTransfer(PROOF, PUB, "double-spend");

  const finalState = await E(publicFacet).getState();
  await E(testNode).setValue(JSON.stringify({ good, tampered, replay, finalState }));
};

run;

#! false node --ignore-this-line
/* global E */
/// <reference types="@agoric/vats/src/core/core-eval-env"/>

// ADR 0014 M6b live proof: the contract builds the Merkle tree ITSELF via the mimcHash bridge (no seedRoot).
//   1. transfer before depositing       -> rejected (root not in the contract tree)
//   2. deposit cmIn                      -> contract computes a root ON-CHAIN; it must EQUAL the proof's root
//   3. transfer (hardened, owner-bound)  -> accepted; outputs inserted as new notes
//   4. replay                            -> rejected (nullifier)
//   5. tampered                          -> rejected (fail closed)
// rootsMatch:true is the M6b claim — the on-chain tree reproduces the circuit's root with no trust.

const BUNDLE_ID =
  "b1-a0960defa2d091969d47b369dcc212d89e89198d3b4690be2c802948875ababb97a09447391f55dd16e9dedf81d4368079e9e93c012d703e659fd40c14549466";

const CMIN = "9362093609897880213715847488021645276594673048062623702389064095374197875375";
const PROOF_ROOT = "6708786935962425648569327983369509322442700570291118589516429311654542325390";

const VK =
  "xSAx5cMJDu7AySHBUFkAt5ly8S22ZKNxTz5bDVHg0RWO/BtF+qTBxng3E/1zZ+WZPGWfo+2RywHttIGSenvOYYN6xHn0xgSE6OEjqTKE6DbAZEDVhDQgkgCg5hLCqziRJ5J4duHSDYEJXv1xcNG7g4FaBDo8/G0g5tvH1NJD10qZjpOTkg1IOnJgv7cx+10l8apJMzWp5xKX5IW3rvMSwhgA3u8SHx52QmoAZl5cRHlnQyLU917a3UbevVzZkvbt5yKSeBxlPwQyFitc0tOfoXNvTOYTyo0nI6GM185SL4rTHDyoHRBOe/ZoF8oA2FucKkF4AQjDpU2wrL3Z7bCkWRs9oLBIiouP8JLQeSURntibabtacwzt9WJ/plHyxZvbAAAABupGoenpG0oQhvy94ZZg/bOqHqpS5DFbwylICSjrWDRyrvoHC+2rXVKZ1jBWlinsQJSDt9bIhABN6tEdK0RNQZWS9AeYzxaDRtOqu4ogopertX1XxnDCHPS8iQAvVs+VadQ9RR1GXIzTHipgFYqqVic1kAEINhMiXilf0N7UOJbFxp4uThhtMY+SownpoZLTzPppt2G3P4ZQo7HNnag69naRuK0c6FyhfedxuWeY0K6SV1Jh3Jp9hgfh1xZjt9uqaAAAAAAAAAAA";
const PROOF =
  "n40nqAoa4kBSnvJudzpcABmdJp55zTwnT78jHOhoNiqV9ZQZc1GYVfvuuczdPlYnZNIg9S73SjrkNyMuO05zDgAlAS34Z2yETEm2j8Rg8JScrJZ6S33i3Za/fFp2Spxq0KvGa+iZxIZio8L3Oj5xEgEO47aWB9hWlXVeuMAZ5LUAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PUB =
  "AAAABQAAAAAAAAAFDtUJ8apMrSyk+weAac6K/2HofhXYli/oPaaTWeSeNo4WomwFdZk7uUrlJy0QufuS1fFOtwwRIQ2iM8+vbfL8Ei7TjYEg9a2eaXRsboAQcP2cRKWadQ2rqYMhYVREgZySGUODSM3bIlIqnaOMNpIfVRqZlGVPLJm0uzFKQE+xi4sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw==";

const run = async powers => {
  const {
    consume: { bridgeManager, zoe, chainStorage },
  } = powers;

  const bm = await bridgeManager;
  const zkVerify = await E(bm).register("zkVerify");
  const mimcHash = await E(bm).register("mimcHash");

  const storageNode = await E(chainStorage).makeChildNode("shieldedTree");
  const testNode = await E(chainStorage).makeChildNode("shieldedTreeTest");

  const installation = await E(zoe).installBundleID(BUNDLE_ID);
  const { publicFacet, creatorFacet } = await E(zoe).startInstance(
    installation,
    harden({}),
    harden({}),
    harden({ zkVerify, mimcHash, vk: VK, storageNode }),
  );

  const doTransfer = async (proof, pub, label) => {
    const inv = await E(publicFacet).makeTransferInvitation();
    const seat = await E(zoe).offer(inv, harden({}), harden({}), harden({ proof, pub }));
    try {
      return { label, accepted: true, result: await E(seat).getOfferResult() };
    } catch (err) {
      return { label, accepted: false, error: String((err && err.message) || err) };
    }
  };

  const beforeDeposit = await doTransfer(PROOF, PUB, "before-deposit");
  const dep = await E(creatorFacet).deposit(CMIN); // contract computes the root on-chain via mimcHash
  const rootsMatch = dep.root === PROOF_ROOT; // the M6b claim: on-chain tree reproduces the circuit root
  const good = await doTransfer(PROOF, PUB, "valid");
  const replay = await doTransfer(PROOF, PUB, "double-spend");
  const i = 12;
  const badProof = PROOF.slice(0, i) + (PROOF[i] === "A" ? "B" : "A") + PROOF.slice(i + 1);
  const tampered = await doTransfer(badProof, PUB, "tampered");

  const finalState = await E(publicFacet).getState();
  await E(testNode).setValue(
    JSON.stringify({ depositRoot: dep.root, proofRoot: PROOF_ROOT, rootsMatch, beforeDeposit, good, replay, tampered, finalState }),
  );
};

run;

#! false node --ignore-this-line
/* global E */
/// <reference types="@agoric/vats/src/core/core-eval-env"/>

// ADR 0014 M4c live proof: install + start the shielded-pool contract, then exercise the unlinkable transfer
// with a WASM-GENERATED proof (from the gnark prover compiled to WASM, M4b):
//   1. transfer BEFORE seeding the root  -> rejected (unknown root)
//   2. seed the root, then transfer      -> accepted (Merkle membership + nullifier verified on-chain)
//   3. replay the same proof             -> rejected (nullifier already used)
//   4. tampered proof                    -> rejected (fail closed)
// The spend reveals a NULLIFIER, not the input commitment -> unlinkable. Outcomes go to vstorage.

const BUNDLE_ID =
  "b1-9eed5bf3f29658e9916d44b9d7a4d19f510f84802c312764f4a9598e710546e17d1cd0b658ed35f3c2197dc01fec31e2522bfa8a2462b13250a00d450d8d6f3c";

// the Merkle root the WASM proof was generated against (public[0])
const ROOT =
  "19757816064155200034491898928102939274701987986801468254297838870612786379351";

// WASM-generated artifacts (gnark prover compiled to GOOS=js GOARCH=wasm; secrets never left the prover)
const VK =
  "4Di+Fk6LIZKRAZIdcCy5Km+aXwMciXP7ZXLJtvPgeZ3b/zGidSiIceyETW0iFaUohqX6Wn3WHFj0KUGc0dhYdOb/155tXPIudtxvyY7cK1YnaUBiWslWCY2P2N24ZuIREOtL1qtBQYw2JNCZ4rMyX9h04vq6PMMLd3a+Dkc+HzTPXjMUPF5gf54+qondKeaQQv8CrKNaR3WzjC74KsCbCB+wbuhaXBBVP/+Eu8reAbsPHw3UiP+SrkQofyT5XTLbjFhI6CYXrZj2/kXr99C44UkDKpJ1B2jEejMVlMSvDUWHFNCelCzCPkFd2aPj6Pi2YZlt+lpghqclxv74AGF30CIRfxYcZdQe+vCYbYnGQ0zJ7K/vFmZhCWscp6WH7dljAAAABuf+CzFbMJwWSJ3a+FTBCTFQV/Bn8mC0kXWfWmD3lQVlkmnY8QPZ+pm0MzFeyE35d3GrISpACmRjf3OiXbAldsrMFb6ZQOpsvW6LkU7Me0g4+bybROCkYlrZG3CO34iRIYu7n8BgXGymf3ZvXAEemCTQ/RXNZqTwS8dUDN3PxpXG3xzRZYj/M+BsNWeVe5u1c8TB/3Ny0qRQ1y2TeohxEbCqXN3CuX7AxdiFCLd5NOwvoW3rA2hTLHiShwQit72jdgAAAAAAAAAA";
const PROOF =
  "3qA4t/beskk41EKHpZ7cKKZ25WsQN3pMJ7f5nxQtqD7dEJLJw6I3QoypTv/P4OZ5M5/nZ+azIPXam36/IZcx1hEVMVHjefEmaOO4V4po1brGVI2jg+BXzOjKCk9GpUKwlhHdvc5kyM2tfd007D4722xoduJfya1EeFr7H/shVVgAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PUB =
  "AAAABQAAAAAAAAAFK66HELFyaiMI/Q4EAUsXAxqsXr2hCrn6jXUNtYlpelcDMCjnPYfiAV6qzw2yl2ak49BGGL3BULkB5T4mZCGmLRlMpB9bPkLBNElgvZilJynko81F0LrtKrlriKeunqKRBBqfA1Yna0EWfNepR/llfaZZ46GCMp3aPBTMHR3IvBoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw==";

const run = async powers => {
  const {
    consume: { bridgeManager, zoe, chainStorage },
  } = powers;

  const bm = await bridgeManager;
  const zkVerify = await E(bm).register("zkVerify");

  const storageNode = await E(chainStorage).makeChildNode("shieldedPool");
  const testNode = await E(chainStorage).makeChildNode("shieldedPoolTest");

  const installation = await E(zoe).installBundleID(BUNDLE_ID);
  const { publicFacet, creatorFacet } = await E(zoe).startInstance(
    installation,
    harden({}),
    harden({}),
    harden({ zkVerify, vk: VK, storageNode }),
  );

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

  // 1. before seeding the root → must be rejected (unknown root)
  const beforeSeed = await doTransfer(PROOF, PUB, "before-seed");

  // 2. seed the root, then transfer → accepted
  await E(creatorFacet).seedRoot(ROOT);
  const good = await doTransfer(PROOF, PUB, "valid");

  // 3. replay → rejected by the nullifier set
  const replay = await doTransfer(PROOF, PUB, "double-spend");

  // 4. tamper one base64 char of the proof → rejected (fail closed)
  const i = 12;
  const badProof = PROOF.slice(0, i) + (PROOF[i] === "A" ? "B" : "A") + PROOF.slice(i + 1);
  const tampered = await doTransfer(badProof, PUB, "tampered");

  const finalState = await E(publicFacet).getState();
  await E(testNode).setValue(JSON.stringify({ beforeSeed, good, replay, tampered, finalState }));
};

run;

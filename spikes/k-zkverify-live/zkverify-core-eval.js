#! false node --ignore-this-line
/* global E */
/// <reference types="@agoric/vats/src/core/core-eval-env"/>

// ADR 0014 live proof: a swingset core-eval calls the native zkVerify bridge port with a REAL
// confidential-transfer proof (gnark Groth16/BN254, from moimoi spikes/i), and a tampered copy.
// Results are written to vstorage at published.zkVerifyProof so they can be queried deterministically.
const VK =
  "o9NRMsXElrd/HyA5Kd5bNMOTX/0uO/jp/PHtAxyOkgyAcZbitMjaFWExK+8EGxJxWANJaddx2Xn54Gf5fHxc0YoX7PxIz6EvmzmaDcvOdVbKombkaSppMLUn7loKIZd1FvMlXZ+C/eOZ2lupQbEgE+zKIzdm7IKaPgPqZ3r2+NapBcZ6rA5YkEO/Y5AwU8ujQDRZ2FutnNJqS/UMwziMFxb46KiS5lgLEXHVdhpNnlejQ+ZgFp9kgMAs7vdVdFtNyPslLJg3VMkf4BhZG2Q2KjlKqd8D4ujAUOfWHvuDFP2WnIcJwgE+BsSIYclJ2XToo+PmB6Up5kWW9a+fdXhrahMAlYtpwiodZo8vrE6Q6q02sT6fWkTh4pHQNd62HchlAAAABcVwffPd+WMVmrkkI9H3ptETm/4q3HN2Q0hivymlLoE/2udOkEVXkgKy42/xMc4ICVKiJIj4eu5t6C7W/44neZ3G1s+5tJbmBrzHF8M2VJVptVbjhXeOSUQP4yCUsWPpMJGFzN+fPeNvKga8mirRZr+PtyHPGrpVTOUpcuwjKc/whhpX5aB7Kzp8m1EPsPVcg+R+ivz+rgUix7XTAOP7ig8AAAAAAAAAAA==";
const PROOF =
  "gb3QXra6eZraYJDlIrGY0dqPXu5LI2e2lETJAxFA2kaMaOD6dWIkNcYjlUYewt5UiNmyI+BuboIAwQJ/ODDCsCmB/SyWfo2wPjl1J5/okXfeLgndl4fExMtgK+v85oNupvDBb/po42xXqweX2nQhkbimUyHLrortAKllzjNyGQkAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PUB =
  "AAAABAAAAAAAAAAEGROeAAUnLVu4IN42AIz8S7q/79n0SOsS+DVkeiR6xxQPGOmRidjBk6t6XlxcXnVGic5GIjHbO7znW1otHoo8dAgNVPjTYTj8ecVyE8prfrcyhXGbmFrT+NC3g2VkWFBPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=";

const TYPE = "VERIFY_GROTH16_BN254";

const proveZkOnChain = async powers => {
  const {
    consume: { bridgeManager, chainStorage },
  } = powers;
  const bm = await bridgeManager;
  const zk = await E(bm).register("zkVerify");

  const good = await E(zk).toBridge({ type: TYPE, vk: VK, proof: PROOF, pub: PUB });

  // tamper: swap one base64 char (stays valid base64, corrupts the proof bytes -> verify must fail closed)
  const i = 12;
  const badChar = PROOF[i] === "A" ? "B" : "A";
  const badProof = PROOF.slice(0, i) + badChar + PROOF.slice(i + 1);
  const tampered = await E(zk).toBridge({ type: TYPE, vk: VK, proof: badProof, pub: PUB });

  const node = E(chainStorage).makeChildNode("zkVerifyProof");
  await E(node).setValue(JSON.stringify({ good, tampered, circuit: "groth16-bn254-transfer" }));
};

proveZkOnChain;

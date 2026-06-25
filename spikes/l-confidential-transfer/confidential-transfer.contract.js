// @ts-nocheck
// ADR 0014 M3 — confidential-transfer Zoe contract (moimoi).
//
// A shielded note ledger. Notes are MiMC commitments to (amount, blind); the amounts stay hidden. A confidential
// `transfer` submits a Groth16/BN254 proof (circuit: moimoi spikes/i) that is verified by the NATIVE `zkVerify`
// bridge port — on consensus, off the XS computron meter. The proof guarantees value CONSERVATION (in == out0 +
// out1 + fee) and 64-bit RANGE in zero-knowledge; the contract adds spend-once (a nullifier set) and binds its
// ledger to the verifier-AUTHENTICATED public inputs (so a caller cannot claim commitments the proof didn't cover).
//
// Offer-safe by construction: the transfer invitation carries an empty proposal, so the seat has nothing to lose;
// the ledger transition happens only after the proof verifies, else the offer is rejected with no state change.
//
// privateArgs: { zkVerify: ScopedBridgeManager<'zkVerify'>, vk: base64 string, storageNode?: StorageNode }
import { E, Far } from '@endo/far';

const TYPE = 'VERIFY_GROTH16_BN254';

export const start = async (zcf, privateArgs) => {
  const { zkVerify, vk, storageNode } = privateArgs;
  assert(zkVerify, 'privateArgs.zkVerify (the zkVerify bridge) is required');
  assert(typeof vk === 'string', 'privateArgs.vk (base64 verifying key) is required');

  const commitments = new Set(); // known note commitments (decimal field-element strings)
  const nullifiers = new Set(); // spent commitments
  let feeTotal = 0n;
  let transfers = 0;

  const publish = async () => {
    if (!storageNode) return;
    await E(storageNode).setValue(
      JSON.stringify({
        commitments: [...commitments],
        nullifiers: [...nullifiers],
        feeTotal: String(feeTotal),
        transfers,
      }),
    );
  };

  // deposit stub: record a note. (A full shield proves commitment == MiMC(depositAmount, blind) and escrows
  // real value; that value layer is the next milestone. Here it seeds the ledger for the transfer mechanism.)
  const seedNote = async commitment => {
    commitments.add(String(commitment));
    await publish();
    return 'seeded';
  };

  // The star: verify a confidential-transfer proof natively, then apply the conserved transition.
  const transferHandler = async (seat, offerArgs) => {
    try {
      const { proof, pub } = offerArgs || {};
      assert(proof && pub, 'transfer needs offerArgs { proof, pub } (base64)');

      const res = await E(zkVerify).toBridge({ type: TYPE, vk, proof, pub });
      assert(res && res.ok, 'zkVerify: proof rejected (invalid or malformed)');

      // res.public is AUTHENTICATED by the verifier: [CommIn, CommOut0, CommOut1, Fee], decimal field strings.
      const [cIn, cOut0, cOut1, fee] = res.public;
      assert(commitments.has(cIn), 'unknown input note (not in the ledger)');
      assert(!nullifiers.has(cIn), 'double-spend: input note already spent');

      // conserved + in-range (guaranteed by the SNARK); spend-once (enforced here).
      nullifiers.add(cIn);
      commitments.add(cOut0);
      commitments.add(cOut1);
      feeTotal += BigInt(fee);
      transfers += 1;

      seat.exit();
      await publish();
      return harden({ ok: true, spent: cIn, created: [cOut0, cOut1], fee });
    } catch (err) {
      seat.exit(err); // offer-safe: nothing escrowed, no state changed on the failure paths above
      throw err;
    }
  };

  const publicFacet = Far('ConfidentialTransfer public', {
    makeTransferInvitation: () =>
      zcf.makeInvitation(transferHandler, 'confidential-transfer'),
    getState: () =>
      harden({
        commitments: [...commitments],
        nullifiers: [...nullifiers],
        feeTotal: String(feeTotal),
        transfers,
      }),
  });

  const creatorFacet = Far('ConfidentialTransfer creator', { seedNote });

  await publish();
  return harden({ publicFacet, creatorFacet });
};
harden(start);

/**
 * fund-onboarding.js — bootstrap core-proposal: seed IST onboarding.
 *
 * Fixes the spike-(b) chicken-and-egg: on a stock chain nobody can get IST (provisionPool unfunded,
 * provisioning costs 0.25 IST). At bootstrap, core proposals run with full powers and NO governance,
 * so we mint IST here and deposit it into a faucet address's vbank — the platform seeds first-IST.
 *
 * Shape mirrors @agoric/builders init-* scripts: a `defaultProposalBuilder` (deploy/extract context)
 * pointing `sourceSpec` at THIS module's behavior + `getManifestForFundOnboarding`. No
 * @agoric/deploy-script-support import, so the module stays safe to bundle into the bootstrap vat.
 *
 * OPEN QUESTION (settle at boot): is `feeMintAccess` still consumable after the initial supply mint?
 * If the log shows it never resolves / errors, switch the IST source (mints vat / reserve).
 */
import { E } from '@endo/far';

/** The core-eval behavior — runs in the bootstrap vat with the granted powers. */
export const fundOnboarding = async (
  { consume: { feeMintAccess: feeMintAccessP, zoe, agoricNames, bankManager } },
  { options },
) => {
  const { faucetAddress, istValue, poolIstValue } = options;
  const [feeMintAccess, zoeService, names, bankMgr] = await Promise.all([
    feeMintAccessP,
    zoe,
    agoricNames,
    bankManager,
  ]);

  const istBrand = await E(names).lookup('brand', 'IST');
  const centralSupply = await E(names).lookup('installation', 'centralSupply');

  // Mint a one-time IST bootstrap payment via centralSupply (the canonical IST issuance path).
  const mintIST = async value => {
    const { creatorFacet } = await E(zoeService).startInstance(
      centralSupply,
      {},
      { bootstrapPaymentValue: BigInt(value) },
      harden({ feeMintAccess }),
    );
    return E(creatorFacet).getBootstrapPayment();
  };

  const depositTo = async (address, payment) => {
    const bank = await E(bankMgr).getBankForAddress(address);
    const purse = await E(bank).getPurse(istBrand);
    return E(purse).deposit(payment);
  };

  // 1) FUND THE PROVISIONPOOL — this is what makes onboarding automatic. The 0.25-IST provisioning
  //    charge is drawn from the pool's funding purse (= its `vbank/provision` bank IST purse), NOT the
  //    user's bank. Funding it here means provisioning (manual AND auto) succeeds out of the box.
  const poolAddr = await E(bankMgr).getModuleAccountAddress('vbank/provision');
  await depositTo(poolAddr, await mintIST(poolIstValue));
  console.log(`fund-onboarding: funded provisionPool (${poolAddr}) with ${poolIstValue} uist`);

  // 2) Also seed a faucet address with IST (distribution / dev convenience).
  if (faucetAddress) {
    await depositTo(faucetAddress, await mintIST(istValue));
    console.log(`fund-onboarding: deposited ${istValue} uist to faucet ${faucetAddress}`);
  }
};
harden(fundOnboarding);

/** Manifest: the powers the behavior may consume. */
export const getManifestForFundOnboarding = (_powers, options) =>
  harden({
    manifest: {
      [fundOnboarding.name]: {
        consume: {
          feeMintAccess: true,
          zoe: true,
          agoricNames: true,
          bankManager: true,
        },
      },
    },
    options,
  });

/** Builder referenced by the bootstrap config's coreProposals entry. */
export const defaultProposalBuilder = async (_builderPowers, opts = {}) =>
  harden({
    // Lives in @agoric/vats/src/proposals so its `@endo/far` import resolves at bundle time
    // (packages/vm-config doesn't carry @endo/far in its closure).
    sourceSpec: '@agoric/vats/src/proposals/fund-onboarding.js',
    getManifestCall: ['getManifestForFundOnboarding', opts.options ?? opts],
  });

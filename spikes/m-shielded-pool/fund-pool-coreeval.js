/* global E, harden */
/// <reference types="@agoric/vats/src/core/core-eval-env"/>
// ADR 0014 M7d — fund the provisionPool (vbank/provision IST purse) so smart-wallet provisioning works.
// Replicates moimoi's fund-onboarding.js as a post-bootstrap core-eval. The 0.25-IST provisioning charge is
// drawn from vbank/provision; an unfunded pool => provision-one SMART_WALLET no-ops (walletsProvisioned stays 0).
const run = async powers => {
  const { consume: { feeMintAccess: fmaP, zoe, agoricNames, bankManager } } = powers;
  const [feeMintAccess, zoeService, names, bankMgr] = await Promise.all([fmaP, zoe, agoricNames, bankManager]);
  const istBrand = await E(names).lookup('brand', 'IST');
  const centralSupply = await E(names).lookup('installation', 'centralSupply');
  const mintIST = async value => {
    const { creatorFacet } = await E(zoeService).startInstance(
      centralSupply, {}, { bootstrapPaymentValue: BigInt(value) }, harden({ feeMintAccess }),
    );
    return E(creatorFacet).getBootstrapPayment();
  };
  const poolAddr = await E(bankMgr).getModuleAccountAddress('vbank/provision');
  const bank = await E(bankMgr).getBankForAddress(poolAddr);
  const purse = await E(bank).getPurse(istBrand);
  await E(purse).deposit(await mintIST(1000000000n)); // 1000 IST
  console.log('fund-pool: funded provisionPool', poolAddr, 'with 1000 IST');
};
run;

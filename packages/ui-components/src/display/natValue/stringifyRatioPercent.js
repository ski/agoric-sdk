// @ts-check

import { assert } from '@agoric/assert';
import { isNatValue } from '@agoric/ertp';

// eslint-disable-next-line import/no-extraneous-dependencies
import '@agoric/zoe/exported';

import { stringifyNat } from './stringifyNat';

const PLACES_TO_SHOW = 2;

/**
 * 
 * @param {Ratio} ratio 
 * @param {{ numDecimalPlaces?: number,
    numPlacesToShow?: number,
    denomDecimalPlaces?: number,
    denomPlacesToShow?: number,
    getDecimalPlaces?: Function }} [options] 
 * @returns {string}
 */
export const stringifyRatioPercent = (ratio, options) => {
  const { numPlacesToShow = PLACES_TO_SHOW, getDecimalPlaces = undefined } =
    options || {};
  let { numDecimalPlaces } = options || {};

  assert(isNatValue(ratio.numerator.value));
  assert(isNatValue(ratio.denominator.value));

  assert(
    ratio.numerator.brand === ratio.denominator.brand,
    `percents are currently limited to the same brand`,
  );

  if (getDecimalPlaces !== undefined) {
    numDecimalPlaces = getDecimalPlaces(ratio.numerator.brand);
  }

  // numDecimalPlaces can be reused for denomDecimalPlaces too
  assert(numDecimalPlaces !== undefined, `numDecimalPlaces required`);

  const result =
    Number(ratio.numerator.value) / Number(ratio.denominator.value);

  console.log(result);

  return `${result}`;

  // return stringifyNat(result, numDecimalPlaces, numPlacesToShow);
};

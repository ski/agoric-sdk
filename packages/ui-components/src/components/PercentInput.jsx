import { makeRatio } from '@agoric/zoe/src/contractSupport';

import { assert } from '@agoric/assert';
import makeNumberFormatPercent from './NumberFormatPercent';

import { parseAsNat } from '../display/natValue/parseAsNat';
import { stringifyNat } from '../display/natValue/stringifyNat';

const PERCENT_BASE = 100n;
// The decimalPlaces parameter attempts to allow control of the number of decimal
// places, but doesn't completely succeed. tpp(102.35) => 102,
// tpp(102.35, 1) => 102, tpp(102.35, 2) => 102.35, tpp(102.35, 3) => 102.35
export function toPrintedPercent(ratio, placesToShow = 0n) {
  if (ratio === null) {
    return '0';
  }
  const power = 10n ** placesToShow;
  const raw =
    (ratio.numerator.value * PERCENT_BASE * power) / ratio.denominator.value;
  return `${Number(raw) / Number(power)}`;
}

// https://material-ui.com/api/text-field/

// Because we are importing the ui-components from the locally linked
// version of agoric-sdk, we must make sure that we are not using
// multiple instances of React and MaterialUI. Thus, we pass the
// instances to the component.

const makePercentInput = ({ React, TextField, NumberFormat }) => ({
  label,
  ratio,
  numeratorDecimalPlaces = 0,
  placesToShow = 2,
  disabled,
  error,
  onChange,
  required,
  helperText,
}) => {
  const NumberFormatPercent = makeNumberFormatPercent({ React, NumberFormat });

  assert(
    ratio.numerator.brand === ratio.denominator.brand,
    `percents are currently limited to the same brand`,
  );

  // No negative values allowed in the input
  // Also, format as a percent
  const inputProps = {
    inputProps: { min: 0 },
    inputComponent: NumberFormatPercent,
  };

  const preventSubtractChar = e => {
    if (e.key === 'Subtract') {
      e.preventDefault();
      e.stopPropagation();
    }
  };

  return (
    <TextField
      label={label}
      type="number"
      fullWidth
      variant="outlined"
      InputProps={inputProps}
      value={toPrintedPercent(ratio)}
      onKeyPress={preventSubtractChar}
      onChange={ev => {
        const numeratorValue = parseAsNat(
          ev.target.value,
          numeratorDecimalPlaces,
        );
        return onChange(
          makeRatio(
            numeratorValue,
            ratio.numerator.brand,
            ratio.denominator.value,
            ratio.denominator.brand,
          ),
        );
      }}
      disabled={disabled}
      error={error}
      required={required}
      helperText={helperText}
    />

    // onChange={ev => onChange(parseAsNat(ev.target.value, decimalPlaces))}

    // value={
    //   value === null ? '0' : stringifyNat(value, decimalPlaces, placesToShow)
    // }
  );
};

export default makePercentInput;

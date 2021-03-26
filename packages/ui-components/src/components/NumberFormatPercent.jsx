// @ts-check

const makeNumberFormatPercent = ({ React, NumberFormat }) => ({
  inputRef,
  onChange,
  ...other
}) => (
  <NumberFormat
    {...other}
    getInputRef={inputRef}
    onValueChange={values => {
      onChange({
        target: {
          value: values.value,
        },
      });
    }}
    thousandSeparator
    suffix="%"
  />
);

export default makeNumberFormatPercent;

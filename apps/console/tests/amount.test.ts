import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDecimalUnits } from "../src/lib/amount";

test("decimal amounts preserve base units beyond Number precision and reject rounding", () => {
  assert.equal(
    parseDecimalUnits("0.125000000000000001", 18),
    "125000000000000001",
  );
  assert.equal(parseDecimalUnits("1.234567891", 9), "1234567891");
  assert.equal(parseDecimalUnits("0.000000001", 9), "1");
  assert.equal(parseDecimalUnits("17", 9), "17000000000");
  assert.equal(parseDecimalUnits("0", 9), "0");
  for (const invalid of [
    "1.0000000001",
    "1e3",
    "-1",
    "1,000",
    "",
    " 1 ",
    "1.",
    "Infinity",
  ]) {
    assert.equal(parseDecimalUnits(invalid, 9), null, invalid);
  }
});

// Decimal input is exact or rejected. Never round away precision or use Number.
export function parseDecimalUnits(
  value: string,
  decimals: number,
): string | null {
  if (value.length > 100 || !/^\d+(\.\d+)?$/.test(value)) return null;
  const [whole, fraction = ""] = value.split(".");
  if (fraction.length > decimals) return null;
  return BigInt(whole + fraction.padEnd(decimals, "0")).toString();
}

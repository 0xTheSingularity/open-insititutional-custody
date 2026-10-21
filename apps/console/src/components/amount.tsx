import type { SampleAsset } from "@/lib/sample-treasury";

export function Amount({
  units,
  asset,
}: {
  units: string;
  asset: SampleAsset;
}) {
  // Base units never pass through Number, including values beyond 2^53.
  const digits = BigInt(units)
    .toString()
    .padStart(asset.decimals + 1, "0");
  const integer = asset.decimals ? digits.slice(0, -asset.decimals) : digits;
  const whole = integer.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const fraction = asset.decimals
    ? digits.slice(-asset.decimals).replace(/0+$/, "")
    : "";
  return (
    <span
      className="font-mono text-sm break-all tabular-nums"
      title={`${units} base units`}
    >
      {whole}
      {fraction ? `.${fraction}` : ""}{" "}
      <span className="text-xs text-muted-foreground">{asset.symbol}</span>
    </span>
  );
}

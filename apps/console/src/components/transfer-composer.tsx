"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeft, ArrowRight, LockKeyhole } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Amount } from "@/components/amount";
import { SampleFreshness } from "@/components/treasury";
import { parseDecimalUnits } from "@/lib/amount";
import type { SampleTreasury } from "@/lib/sample-treasury";

export function TransferComposer({ treasury }: { treasury: SampleTreasury }) {
  const search = useSearchParams();
  const backFilters = new URLSearchParams();
  const query = search.get("q");
  const status = search.get("status");
  if (query) backFilters.set("q", query);
  if (status === "attention" || status === "finalized")
    backFilters.set("status", status);
  const [vaultId, setVaultId] = useState(
    search.get("vault") ?? treasury.holdings[0].id,
  );
  const vault =
    treasury.holdings.find((item) => item.id === vaultId) ??
    treasury.holdings[0];
  const destinations = treasury.transfers.filter(
    (item, index, all) =>
      item.vault === vault.vault &&
      all.findIndex(
        (other) =>
          other.vault === item.vault &&
          other.destination.address === item.destination.address &&
          other.destination.version === item.destination.version,
      ) === index,
  );
  const [destinationId, setDestinationId] = useState("");
  const destination =
    destinations.find((item) => item.id === destinationId) ?? destinations[0];
  const [amount, setAmount] = useState("");
  const [fee, setFee] = useState("");
  const [reference, setReference] = useState("");
  const [purpose, setPurpose] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [review, setReview] = useState<{ amount: string; fee: string } | null>(
    null,
  );
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  function validate() {
    const amountUnits = parseDecimalUnits(amount, vault.asset.decimals);
    const feeUnits = parseDecimalUnits(fee, vault.asset.decimals);
    const next: Record<string, string> = {};
    if (!reference.trim())
      next.reference = "Enter a public sample business reference.";
    else if (
      treasury.transfers.some(
        (item) =>
          item.reference.toLowerCase() === reference.trim().toLowerCase(),
      )
    )
      next.reference =
        "This reference already exists in the sample. Inspect that transfer instead of creating a duplicate.";
    if (!purpose.trim())
      next.purpose = "Describe the sample payment's purpose.";
    if (amountUnits === null)
      next.amount = `Use a decimal with no more than ${vault.asset.decimals} fractional digits. No exponent, commas or rounding.`;
    else if (BigInt(amountUnits) === 0n)
      next.amount = "Amount must be greater than zero.";
    if (feeUnits === null)
      next.fee = `Enter a native fee ceiling with at most ${vault.asset.decimals} fractional digits.`;
    else if (BigInt(feeUnits) === 0n)
      next.fee = "Use a positive fee ceiling for this example.";
    if (
      amountUnits !== null &&
      feeUnits !== null &&
      BigInt(amountUnits) + BigInt(feeUnits) > BigInt(vault.available_units)
    )
      next.amount =
        "Amount plus maximum fee exceeds the sample available balance. Existing reservations remain excluded.";
    setErrors(next);
    if (Object.keys(next).length) {
      requestAnimationFrame(() =>
        document.getElementById(Object.keys(next)[0])?.focus(),
      );
      return;
    }
    setReview({ amount: amountUnits!, fee: feeUnits! });
    requestAnimationFrame(() => reviewHeading.current?.focus());
  }
  function errorFor(field: string) {
    return errors[field] ? (
      <p id={`${field}-error`} className="text-sm text-destructive">
        {errors[field]}
      </p>
    ) : null;
  }
  return (
    <div className="space-y-6">
      <Button asChild variant="outline">
        <Link href={`/transfers${backFilters.size ? `?${backFilters}` : ""}`}>
          <ArrowLeft aria-hidden="true" />
          Back to transfers
        </Link>
      </Button>
      <Alert>
        <LockKeyhole aria-hidden="true" />
        <AlertTitle>Explore the review. No request is created.</AlertTitle>
        <AlertDescription>
          Public examples only. Input stays in this page's memory and is
          discarded on navigation. No policy, chain, address ownership or
          approval check runs. Do not enter private business data.
        </AlertDescription>
      </Alert>
      {!review ? (
        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_20rem]">
          <Card>
            <CardHeader>
              <CardTitle>
                <h2>Sample transfer</h2>
              </CardTitle>
              <CardDescription>
                Choose a source and versioned destination, then enter exact
                native amounts.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form
                className="space-y-6"
                noValidate
                onSubmit={(event) => {
                  event.preventDefault();
                  validate();
                }}
              >
                <div className="space-y-2">
                  <Label htmlFor="source-vault">Source vault</Label>
                  <Select
                    value={vault.id}
                    onValueChange={(value) => {
                      setVaultId(value);
                      setDestinationId("");
                      setAmount("");
                      setFee("");
                      setErrors({});
                    }}
                  >
                    <SelectTrigger id="source-vault" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {treasury.holdings.map((item) => (
                        <SelectItem key={item.id} value={item.id}>
                          {item.vault}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    {vault.asset.network} · native {vault.asset.symbol}
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="destination">
                    Sample destination reference
                  </Label>
                  <Select
                    value={destination.id}
                    onValueChange={setDestinationId}
                  >
                    <SelectTrigger id="destination" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {destinations.map((item) => (
                        <SelectItem key={item.id} value={item.id}>
                          {item.destination.name} · v{item.destination.version}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <code className="block text-xs break-all">
                    {destination.destination.address}
                  </code>
                  <p className="text-xs text-muted-foreground">
                    Fixture reference only; activation and ownership not
                    verified.
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="reference">Business reference</Label>
                  <Input
                    id="reference"
                    className="h-11"
                    value={reference}
                    maxLength={80}
                    onChange={(event) => setReference(event.target.value)}
                    placeholder="EXAMPLE-2026-043"
                    aria-invalid={!!errors.reference}
                    aria-describedby={
                      errors.reference ? "reference-error" : undefined
                    }
                  />
                  {errorFor("reference")}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="purpose">Purpose</Label>
                  <Textarea
                    id="purpose"
                    value={purpose}
                    maxLength={240}
                    onChange={(event) => setPurpose(event.target.value)}
                    placeholder="Public sample payment description"
                    aria-invalid={!!errors.purpose}
                    aria-describedby={
                      errors.purpose ? "purpose-error" : undefined
                    }
                  />
                  {errorFor("purpose")}
                </div>
                <div className="grid gap-5 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="amount">
                      Amount ({vault.asset.symbol})
                    </Label>
                    <Input
                      id="amount"
                      className="h-11"
                      inputMode="decimal"
                      value={amount}
                      maxLength={100}
                      onChange={(event) => setAmount(event.target.value)}
                      placeholder="0.00"
                      aria-invalid={!!errors.amount}
                      aria-describedby={
                        errors.amount ? "amount-error" : "amount-help"
                      }
                    />
                    {errorFor("amount")}
                    <p
                      id="amount-help"
                      className="text-xs text-muted-foreground"
                    >
                      Up to {vault.asset.decimals} decimals. Never rounded.
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="fee">
                      Maximum native fee ({vault.asset.symbol})
                    </Label>
                    <Input
                      id="fee"
                      className="h-11"
                      inputMode="decimal"
                      value={fee}
                      maxLength={100}
                      onChange={(event) => setFee(event.target.value)}
                      placeholder="0.00"
                      aria-invalid={!!errors.fee}
                      aria-describedby={errors.fee ? "fee-error" : "fee-help"}
                    />
                    {errorFor("fee")}
                    <p id="fee-help" className="text-xs text-muted-foreground">
                      A ceiling, not a live fee estimate.
                    </p>
                  </div>
                </div>
                <Button type="submit" className="h-11">
                  Review sample
                  <ArrowRight aria-hidden="true" />
                </Button>
              </form>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>
                <h2>Source exposure</h2>
              </CardTitle>
              <CardDescription>
                Historical example, not a spend authorization.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <dl className="space-y-5 text-sm">
                {[
                  ["Canonical", vault.canonical_units],
                  ["Already reserved", vault.reserved_units],
                  ["Available in sample", vault.available_units],
                ].map(([label, units]) => (
                  <div key={label}>
                    <dt className="text-muted-foreground">{label}</dt>
                    <dd className="mt-2">
                      <Amount units={units} asset={vault.asset} />
                    </dd>
                  </div>
                ))}
              </dl>
              <p className="border-t pt-4 text-xs leading-relaxed text-muted-foreground">
                Fee estimate, account/rent requirements and fresh chain evidence
                are unavailable. There is no Max action or guarantee this
                transfer is feasible.
              </p>
            </CardContent>
          </Card>
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>
              <h2 ref={reviewHeading} tabIndex={-1} className="outline-none">
                Review sample transfer
              </h2>
            </CardTitle>
            <CardDescription>
              Check the complete request. This is not a verified candidate or a
              policy preview.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <dl className="grid gap-6 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">
                  Workspace / environment
                </dt>
                <dd className="mt-2">Public example · Test only</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">
                  Source / network / asset
                </dt>
                <dd className="mt-2">
                  {vault.vault} · {vault.asset.network} · native{" "}
                  {vault.asset.symbol}
                </dd>
                <p className="mt-1 text-xs text-muted-foreground">
                  {vault.asset.network_identity}
                </p>
              </div>
              <div className="min-w-0">
                <dt className="text-muted-foreground">Full source address</dt>
                <dd className="mt-2">
                  <code className="break-all">
                    {destination.source_address}
                  </code>
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="text-muted-foreground">
                  Full beneficiary / registry version
                </dt>
                <dd className="mt-2">
                  {destination.destination.name} · sample v
                  {destination.destination.version}
                  <code className="mt-2 block break-all">
                    {destination.destination.address}
                  </code>
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Exact amount</dt>
                <dd className="mt-2">
                  <Amount units={review.amount} asset={vault.asset} />
                </dd>
                <p className="mt-1 font-mono text-xs break-all text-muted-foreground">
                  {review.amount} base units
                </p>
              </div>
              <div>
                <dt className="text-muted-foreground">Maximum native fee</dt>
                <dd className="mt-2">
                  <Amount units={review.fee} asset={vault.asset} />
                </dd>
                <p className="mt-1 text-xs text-muted-foreground">
                  Estimate unavailable
                </p>
              </div>
              <div className="min-w-0">
                <dt className="text-muted-foreground">
                  Business reference / purpose
                </dt>
                <dd className="mt-2 break-words">
                  {reference.trim()}
                  <p className="mt-2">{purpose.trim()}</p>
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">
                  Maximum combined exposure in this example
                </dt>
                <dd className="mt-2">
                  <Amount
                    units={(
                      BigInt(review.amount) + BigInt(review.fee)
                    ).toString()}
                    asset={vault.asset}
                  />
                </dd>
              </div>
            </dl>
            <Alert>
              <AlertTitle>
                Policy and authorization are not evaluated
              </AlertTitle>
              <AlertDescription>
                Required approvers, policy epoch, expiry, destination
                activation, verified evidence age and chain requirements are
                unavailable. No intent, idempotency key, approval grant or
                reservation has been created.
              </AlertDescription>
            </Alert>
            <div className="flex flex-wrap gap-3">
              <Button variant="outline" onClick={() => setReview(null)}>
                <ArrowLeft aria-hidden="true" />
                Edit sample
              </Button>
              <Button disabled aria-describedby="submit-unavailable">
                Create transfer request
              </Button>
            </div>
            <p
              id="submit-unavailable"
              className="text-xs text-muted-foreground"
            >
              Requires institution authentication and the custody API. Browser
              review never grants signing authority.
            </p>
          </CardContent>
        </Card>
      )}
      <SampleFreshness treasury={treasury} />
    </div>
  );
}

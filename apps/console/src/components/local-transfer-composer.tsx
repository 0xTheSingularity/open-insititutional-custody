"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { custodyRequest } from "@/lib/custody-client";
import {
  readIntentIds,
  readIntentRecord,
  type CustodyIntentRecord,
  type LocalCatalog,
  type LocalStatus,
} from "@/lib/custody-model";
import {
  pendingStorageKey,
  prepareIntent,
  readPending,
  sameIntent,
  type PendingIntent,
} from "@/lib/custody-draft";

export function LocalTransferComposer({
  catalog,
  status,
  records,
  disabled,
}: {
  catalog: LocalCatalog;
  status: LocalStatus;
  records: CustodyIntentRecord[];
  disabled: boolean;
}) {
  const [walletId, setWalletId] = useState(
    catalog.wallets.find((w) => w.active)?.chain_wallet_id ?? "",
  );
  const wallet = catalog.wallets.find((w) => w.chain_wallet_id === walletId);
  const asset = catalog.assets.find((a) => a.network_id === wallet?.network_id);
  const destinations = catalog.destinations.filter(
    (d) =>
      d.network_id === wallet?.network_id &&
      (!d.allowed_assets.length ||
        d.allowed_assets.includes(asset?.asset_id ?? "")),
  );
  const [destinationId, setDestinationId] = useState("");
  const destination =
    destinations.find(
      (d) => `${d.destination_id}:${d.version}` === destinationId,
    ) ?? destinations[0];
  const [amount, setAmount] = useState("");
  const [fee, setFee] = useState("");
  const [reference, setReference] = useState("");
  const [review, setReview] = useState<PendingIntent | null>(null);
  const [pending, setPending] = useState<PendingIntent | null>(null);
  const [accepted, setAccepted] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [storageFailed, setStorageFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const flight = useRef(false);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    try {
      const raw = localStorage.getItem(pendingStorageKey);
      setPending(raw ? readPending(raw, catalog) : null);
      setAccepted(false);
      setLoaded(true);
    } catch (e) {
      setStorageFailed(true);
      setError((e as Error).message);
    }
  }, [catalog]);
  const saved =
    pending && records.find((r) => sameIntent(pending.intent, r.intent));

  async function create() {
    if (!review || flight.current || disabled || pending || storageFailed)
      return;
    flight.current = true;
    setBusy(true);
    setError("");
    try {
      if (!navigator.locks)
        throw new Error(
          "This browser cannot safely coordinate local requests across tabs. Use a browser with Web Locks on loopback.",
        );
      await navigator.locks.request(pendingStorageKey, async () => {
        const raw = localStorage.getItem(pendingStorageKey);
        if (raw) {
          setPending(readPending(raw, catalog));
          throw new Error(
            "Another tab already prepared a request. Inspect the retained intent; no new request was sent.",
          );
        }
        // The rendered list may predate another tab's completed request.
        const ids = readIntentIds(await custodyRequest("intents"));
        for (const id of ids) {
          const existing = readIntentRecord(
            await custodyRequest(`intents/${encodeURIComponent(id)}`),
          );
          if (
            existing.intent.external_reference.trim().toLowerCase() ===
            review.intent.external_reference.toLowerCase()
          )
            throw new Error(
              "This reference now exists in the custody service. Inspect that transfer before creating another payment.",
            );
        }
        // Persist before the mutating request. A saved request is never
        // automatically sent or retried, even after an unacknowledged response.
        localStorage.setItem(pendingStorageKey, JSON.stringify(review));
        if (localStorage.getItem(pendingStorageKey) !== JSON.stringify(review))
          throw new Error(
            "The request identity could not be retained. No request was sent.",
          );
        setPending(review);
        const record = readIntentRecord(
          await custodyRequest("intents", {
            method: "POST",
            body: review.intent,
            idempotencyKey: review.idempotencyKey,
          }),
        );
        if (!sameIntent(review.intent, record.intent))
          throw new Error(
            "The response differs from the immutable request. Inspect the retained intent. No automatic retry is allowed.",
          );
        setAccepted(true);
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      flight.current = false;
      setBusy(false);
    }
  }

  async function clearAccepted() {
    if (!pending || (!saved && !accepted) || busy) return;
    try {
      await navigator.locks.request(pendingStorageKey, () => {
        const raw = localStorage.getItem(pendingStorageKey);
        if (
          !raw ||
          !sameIntent(pending.intent, readPending(raw, catalog).intent)
        )
          throw new Error(
            "The retained request changed in another tab. Reload before acting.",
          );
        localStorage.removeItem(pendingStorageKey);
        setPending(null);
        setReview(null);
        setAccepted(false);
        setAmount("");
        setFee("");
        setReference("");
        setError("");
      });
    } catch (e) {
      setStorageFailed(true);
      setError((e as Error).message);
    }
  }

  const shown = pending ?? review;
  const shownAsset =
    shown &&
    catalog.assets.find(
      (a) => a.asset_id === shown.intent.operation.asset_transfer.asset_id,
    );
  return (
    <div className="space-y-6">
      {error && (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Request paused</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {pending ? (
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>
                {accepted || saved
                  ? "Intent recorded"
                  : "Request identity retained; outcome not confirmed"}
              </h2>
            </CardTitle>
            <CardDescription>
              No automatic retry or replacement is offered. Reload custody state
              to find this exact intent, including after a process restart.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <p className="font-mono text-sm break-all">
              {pending.intent.intent_id}
            </p>
            <p className="text-sm">{pending.intent.external_reference}</p>
            {shownAsset && (
              <Amount
                units={
                  pending.intent.operation.asset_transfer.amount_base_units
                }
                asset={shownAsset}
              />
            )}
            <div className="flex flex-wrap gap-3">
              <Button asChild>
                <Link
                  href={`/transfers/${encodeURIComponent(pending.intent.intent_id)}`}
                >
                  Inspect retained intent
                </Link>
              </Button>
              <Button
                variant="outline"
                disabled={!saved && !accepted}
                onClick={() => void clearAccepted()}
              >
                Prepare another request
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              The retained request contains public test payment details, not
              keys. It remains in this browser until the API acknowledges it and
              you explicitly start another request. Do not clear browser storage
              to bypass an unknown outcome.
            </p>
          </CardContent>
        </Card>
      ) : !shown ? (
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>New local transfer</h2>
            </CardTitle>
            <CardDescription>
              Use test funds only. The backend builds the candidate; a separate
              approver verifies it before submission.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="space-y-6"
              onSubmit={(event) => {
                event.preventDefault();
                setError("");
                try {
                  setReview(
                    prepareIntent(
                      catalog,
                      status,
                      {
                        walletId,
                        destination: destination
                          ? `${destination.destination_id}:${destination.version}`
                          : "",
                        amount,
                        fee,
                        reference,
                      },
                      records.map((r) => r.intent.external_reference),
                      `console-${crypto.randomUUID()}`,
                      Math.floor(Date.now() / 1000),
                    ),
                  );
                  requestAnimationFrame(() => heading.current?.focus());
                } catch (e) {
                  setError((e as Error).message);
                }
              }}
            >
              <div className="grid gap-6 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="local-wallet">Source wallet</Label>
                  <Select
                    value={walletId}
                    disabled={disabled}
                    onValueChange={(value) => {
                      setWalletId(value);
                      setDestinationId("");
                      setAmount("");
                      setFee("");
                    }}
                  >
                    <SelectTrigger id="local-wallet" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {catalog.wallets
                        .filter((w) => w.active)
                        .map((w) => (
                          <SelectItem
                            key={w.chain_wallet_id}
                            value={w.chain_wallet_id}
                          >
                            {w.chain_wallet_id} · {w.network_id}
                          </SelectItem>
                        ))}
                    </SelectContent>
                  </Select>
                  <code className="block text-xs break-all">
                    {wallet?.address_display}
                  </code>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="local-destination">
                    Versioned beneficiary
                  </Label>
                  <Select
                    value={
                      destination
                        ? `${destination.destination_id}:${destination.version}`
                        : ""
                    }
                    disabled={disabled}
                    onValueChange={setDestinationId}
                  >
                    <SelectTrigger id="local-destination" className="w-full">
                      <SelectValue placeholder="No enrolled destination" />
                    </SelectTrigger>
                    <SelectContent>
                      {destinations.map((d) => (
                        <SelectItem
                          key={`${d.destination_id}:${d.version}`}
                          value={`${d.destination_id}:${d.version}`}
                        >
                          {d.display_name} · v{d.version}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <code className="block text-xs break-all">
                    {destination?.address_display}
                  </code>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="local-reference">Business reference</Label>
                <Input
                  id="local-reference"
                  className="h-11"
                  value={reference}
                  onChange={(e) => setReference(e.target.value)}
                  maxLength={80}
                  required
                  placeholder="LOCAL-TRIAL-001"
                />
              </div>
              <div className="grid gap-6 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="local-amount">Amount ({asset?.symbol})</Label>
                  <Input
                    id="local-amount"
                    className="h-11"
                    inputMode="decimal"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    maxLength={100}
                    required
                  />
                  <p className="text-xs text-muted-foreground">
                    At most {asset?.decimals} decimals. Never rounded.
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="local-fee">
                    Maximum network fee ({asset?.symbol})
                  </Label>
                  <Input
                    id="local-fee"
                    className="h-11"
                    inputMode="decimal"
                    value={fee}
                    onChange={(e) => setFee(e.target.value)}
                    maxLength={100}
                    required
                  />
                  <p className="text-xs text-muted-foreground">
                    A ceiling, not an estimate. Fees come from the native
                    balance.
                  </p>
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Purpose: settlement · exact-candidate approval · at most one
                successful payment. Catalog policy {catalog.policy.policy_id},
                epoch {catalog.policy.policy_epoch}. Policy allowance and
                evidence freshness are evaluated by the backend.
              </p>
              <Button
                type="submit"
                disabled={disabled || !loaded || storageFailed || !destination}
              >
                Review local request
              </Button>
            </form>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>
              <h2 ref={heading} tabIndex={-1} className="outline-none">
                Review immutable request
              </h2>
            </CardTitle>
            <CardDescription>
              Creating a request does not sign, approve or submit the payment.
              Review the backend package independently afterwards.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <dl className="grid gap-6 text-sm sm:grid-cols-2">
              {[
                [
                  "Institution / environment",
                  `${shown.intent.institution_id} / ${shown.intent.environment_id}`,
                ],
                [
                  "Wallet / chain profile",
                  `${shown.intent.chain_wallet_id} / ${shown.intent.chain_profile_id}`,
                ],
                ["Full source address", wallet?.address_display],
                ["Full beneficiary address", destination?.address_display],
                [
                  "Beneficiary / version",
                  `${shown.intent.operation.asset_transfer.destination_id} / v${shown.intent.operation.asset_transfer.destination_version}`,
                ],
                ["Reference", shown.intent.external_reference],
                [
                  "Amount in base units",
                  shown.intent.operation.asset_transfer.amount_base_units,
                ],
                [
                  "Fee ceiling in base units",
                  shown.intent.constraints.max_network_fee_base_units,
                ],
                [
                  "Stable intent and idempotency identity",
                  shown.intent.intent_id,
                ],
              ].map(([label, value]) => (
                <div key={label} className="min-w-0">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="mt-2 break-all">{value}</dd>
                </div>
              ))}
            </dl>
            {shownAsset && (
              <Amount
                units={shown.intent.operation.asset_transfer.amount_base_units}
                asset={shownAsset}
              />
            )}
            <div className="flex flex-wrap gap-3">
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => setReview(null)}
              >
                Edit before creation
              </Button>
              <Button
                disabled={disabled || busy || storageFailed}
                onClick={() => void create()}
              >
                Create local intent
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

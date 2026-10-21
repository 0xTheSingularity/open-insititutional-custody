"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeft, CircleAlert, LockKeyhole, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  TableCaption,
} from "@/components/ui/table";
import { Amount } from "@/components/amount";
import { SampleFreshness } from "@/components/treasury";
import type { SampleTransfer, SampleTreasury } from "@/lib/sample-treasury";

function listQuery(query: string, status: string) {
  const params = new URLSearchParams();
  if (query) params.set("q", query);
  if (status === "attention" || status === "finalized")
    params.set("status", status);
  return params.size ? `?${params}` : "";
}

function TransferStatus({ transfer }: { transfer: SampleTransfer }) {
  return (
    <Badge
      variant="outline"
      className={
        transfer.state === "FinalizedSuccess"
          ? "border-success-border bg-success-surface text-success"
          : "border-warning-border bg-warning-surface text-warning"
      }
    >
      {transfer.state === "SubmissionUnknown"
        ? "Submission uncertain"
        : transfer.state === "AwaitingApproval"
          ? "Awaiting approvals"
          : "Finalized on chain"}
    </Badge>
  );
}

export function TransferListView({ treasury }: { treasury: SampleTreasury }) {
  const search = useSearchParams();
  const query = search.get("q") ?? "";
  const selected = search.get("status");
  const status =
    selected === "attention" || selected === "finalized" ? selected : "all";
  const filtered = treasury.transfers.filter((transfer) => {
    const matchesStatus =
      status === "all" ||
      (status === "finalized"
        ? transfer.state === "FinalizedSuccess"
        : transfer.state !== "FinalizedSuccess" ||
          transfer.reconciliation !== "matched");
    return (
      matchesStatus &&
      [
        transfer.reference,
        transfer.id,
        transfer.purpose,
        transfer.vault,
        transfer.destination.name,
        transfer.destination.address,
        transfer.asset.network,
      ]
        .join(" ")
        .toLowerCase()
        .includes(query.trim().toLowerCase())
    );
  });
  const filters = [
    { id: "all", label: "All transfers" },
    { id: "attention", label: "Needs attention" },
    { id: "finalized", label: "Finalized on chain" },
  ];
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div
          className="flex flex-wrap gap-2"
          aria-label="Transfer status filters"
        >
          {filters.map((filter) => (
            <Button
              asChild
              key={filter.id}
              variant={status === filter.id ? "secondary" : "outline"}
              className="h-11"
            >
              <Link
                href={`/transfers${listQuery(query, filter.id)}`}
                aria-current={status === filter.id ? "true" : undefined}
              >
                {filter.label}
              </Link>
            </Button>
          ))}
        </div>
        <div className="max-w-sm space-y-2">
          <Button
            disabled
            className="h-11"
            aria-describedby="transfer-propose-reason"
          >
            <LockKeyhole aria-hidden="true" />
            Propose transfer
          </Button>
          <p
            id="transfer-propose-reason"
            className="text-xs text-muted-foreground"
          >
            Unavailable without an authenticated custody connection.
          </p>
        </div>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Sample transfers</h2>
          </CardTitle>
          <CardDescription>
            One business request per row. Submission, finality and
            reconciliation are different facts.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <form
            action="/transfers"
            method="get"
            className="flex flex-wrap items-end gap-3"
          >
            <input type="hidden" name="status" value={status} />
            <div className="min-w-0 flex-1 space-y-2 sm:max-w-md">
              <Label htmlFor="transfer-query">Find a sample transfer</Label>
              <Input
                key={query}
                id="transfer-query"
                name="q"
                defaultValue={query}
                maxLength={160}
                placeholder="Business reference, destination or network"
                className="h-11"
              />
            </div>
            <Button variant="outline" type="submit" className="h-11">
              <Search aria-hidden="true" />
              Search
            </Button>
          </form>
          <p role="status" className="text-sm text-muted-foreground">
            {filtered.length} of {treasury.transfers.length} sample transfers
          </p>
          {filtered.length ? (
            <>
              <p className="text-xs text-muted-foreground lg:hidden">
                Scroll the table horizontally for status and reconciliation.
              </p>
              <Table>
                <TableCaption>
                  Static test-network examples, not issued payments or verified
                  audit records.
                </TableCaption>
                <TableHeader>
                  <TableRow>
                    <TableHead>Business request / vault</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Amount</TableHead>
                    <TableHead>Chain lifecycle</TableHead>
                    <TableHead>Reconciliation</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((transfer) => (
                    <TableRow key={transfer.id}>
                      <TableCell className="min-w-52 py-5 whitespace-normal">
                        <Link
                          href={`/transfers/${transfer.id}${listQuery(query, status)}`}
                          className="font-medium text-primary underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                        >
                          {transfer.reference}
                        </Link>
                        <span className="mt-1 block text-xs text-muted-foreground">
                          {transfer.vault}
                        </span>
                        <span className="mt-1 block text-xs text-muted-foreground">
                          {transfer.asset.network}
                        </span>
                      </TableCell>
                      <TableCell className="min-w-44 whitespace-normal">
                        {transfer.destination.name}
                        <span className="mt-1 block text-xs text-muted-foreground">
                          Registry v{transfer.destination.version} · sample
                        </span>
                      </TableCell>
                      <TableCell className="min-w-48 whitespace-normal">
                        <Amount
                          units={transfer.amount_units}
                          asset={transfer.asset}
                        />
                      </TableCell>
                      <TableCell className="min-w-44 whitespace-normal">
                        <TransferStatus transfer={transfer} />
                      </TableCell>
                      <TableCell className="min-w-36 whitespace-normal">
                        <Badge
                          variant="outline"
                          className={
                            transfer.reconciliation === "matched"
                              ? "text-success"
                              : "text-warning"
                          }
                        >
                          {transfer.reconciliation === "matched"
                            ? "Matched (sample)"
                            : "Pending"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </>
          ) : (
            <div className="space-y-3 rounded-lg border border-dashed p-6">
              <h3 className="font-medium">
                No sample transfers match these filters
              </h3>
              <p className="text-sm text-muted-foreground">
                Try a different public business reference, destination or
                status.
              </p>
              <Button asChild variant="outline" className="h-11">
                <Link href="/transfers">Clear filters</Link>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
      <SampleFreshness treasury={treasury} />
    </div>
  );
}

export function TransferDetailView({
  transfer,
  treasury,
}: {
  transfer: SampleTransfer;
  treasury: SampleTreasury;
}) {
  const search = useSearchParams();
  const uncertain = transfer.state === "SubmissionUnknown";
  const awaiting = transfer.state === "AwaitingApproval";
  return (
    <div className="space-y-6">
      <Button asChild variant="outline" className="h-11">
        <Link
          href={`/transfers${listQuery(search.get("q") ?? "", search.get("status") ?? "all")}`}
        >
          <ArrowLeft aria-hidden="true" />
          Back to transfers
        </Link>
      </Button>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold tracking-tight">
            {transfer.reference}
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            {transfer.purpose}
          </p>
        </div>
        <TransferStatus transfer={transfer} />
      </div>
      {uncertain && (
        <Alert className="border-warning-border bg-warning-surface">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>
            A signature may exist. Do not create a duplicate payment.
          </AlertTitle>
          <AlertDescription>
            Missing RPC acknowledgement does not mean failed or cancelled. Keep
            the principal and fee ceiling reserved. Ordinary pre-issuance
            cancellation is no longer safe.
          </AlertDescription>
        </Alert>
      )}
      {!awaiting && !uncertain && transfer.reconciliation === "pending" && (
        <Alert className="border-warning-border bg-warning-surface">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>
            Finalized on chain; reconciliation is still pending.
          </AlertTitle>
          <AlertDescription>
            A finalized chain outcome does not prove that the journal or a
            recipient venue account has matched.
          </AlertDescription>
        </Alert>
      )}
      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>
                <h3>Payment context</h3>
              </CardTitle>
              <CardDescription>
                Public example addresses only. Registry ownership and approvals
                are not verified.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="grid min-w-0 gap-6 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-muted-foreground">Amount</dt>
                  <dd className="mt-2">
                    <Amount
                      units={transfer.amount_units}
                      asset={transfer.asset}
                    />
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Maximum native fee</dt>
                  <dd className="mt-2">
                    <Amount
                      units={transfer.maximum_fee_units}
                      asset={transfer.asset}
                    />
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Vault / network</dt>
                  <dd className="mt-2">
                    {transfer.vault}
                    <span className="mt-1 block">{transfer.asset.network}</span>
                    <span className="mt-1 block text-xs text-muted-foreground">
                      {transfer.asset.network_identity}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Asset identity</dt>
                  <dd className="mt-2">
                    Native {transfer.asset.symbol} · {transfer.asset.decimals}{" "}
                    decimals
                    <span className="mt-1 block text-xs text-muted-foreground">
                      Not a token contract or mint
                    </span>
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-muted-foreground">
                    Source address (example)
                  </dt>
                  <dd className="mt-2 font-mono text-xs break-all">
                    {transfer.source_address}
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-muted-foreground">
                    Full destination (example)
                  </dt>
                  <dd className="mt-2">
                    {transfer.destination.name} · registry v
                    {transfer.destination.version}
                    <code className="mt-2 block text-xs break-all">
                      {transfer.destination.address}
                    </code>
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>
          {uncertain && (
            <Card id="case">
              <CardHeader>
                <CardTitle>
                  <h3>Case: submission acknowledgement missing</h3>
                </CardTitle>
                <CardDescription>
                  Responsible role in this scenario: treasury operations with
                  the broadcaster owner.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 text-sm leading-relaxed">
                <dl className="grid gap-5 sm:grid-cols-2">
                  <div>
                    <dt className="text-muted-foreground">Affected exposure</dt>
                    <dd className="mt-2">
                      <Amount
                        units={transfer.reserved_units}
                        asset={transfer.asset}
                      />
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">
                      Latest sample observation
                    </dt>
                    <dd className="mt-2">
                      <time dateTime={transfer.updated_at}>
                        {transfer.updated_at
                          .replace("T", " ")
                          .replace("Z", " UTC")}
                      </time>
                    </dd>
                  </div>
                </dl>
                <p>
                  Inspect retained issuance and the existing submission attempt.
                  A connected service must reconcile authoritative chain
                  evidence before changing the outcome.
                </p>
                <p className="text-muted-foreground">
                  Identical-byte rebroadcast is only safe when the backend
                  supports it and retains the original signed transaction. This
                  sample has neither that transaction nor a rebroadcast action.
                </p>
              </CardContent>
            </Card>
          )}
          <Card>
            <CardHeader>
              <CardTitle>
                <h3>Sample lifecycle</h3>
              </CardTitle>
              <CardDescription>
                Chronological scenario notes, not signed events or proof of
                sequence completeness.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ol className="ml-2 border-l pl-6">
                {transfer.timeline.map((event) => (
                  <li key={event.time} className="relative pb-7 last:pb-0">
                    <span
                      className="absolute top-1 -left-[1.8rem] size-2.5 rounded-full border-2 border-card bg-primary"
                      aria-hidden="true"
                    />
                    <time
                      dateTime={event.time}
                      className="text-xs text-muted-foreground"
                    >
                      {event.time.slice(11, 16)} UTC · {event.time.slice(0, 10)}
                    </time>
                    <p className="mt-1 text-sm font-medium">{event.title}</p>
                    <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                      {event.detail}
                    </p>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        </div>
        <div className="min-w-0 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>
                <h3>Settlement & exposure</h3>
              </CardTitle>
              <CardDescription>
                Separate chain, accounting and reservation facts.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="space-y-5 text-sm">
                <div>
                  <dt className="text-muted-foreground">
                    Exact lifecycle state
                  </dt>
                  <dd className="mt-1 font-mono text-xs break-all">
                    {transfer.state}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Signature</dt>
                  <dd className="mt-1">
                    {awaiting
                      ? "Not issued in this scenario"
                      : uncertain
                        ? "May exist; issuance committed"
                        : "Issued in this scenario"}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">
                    Reserved incl. fee ceiling
                  </dt>
                  <dd className="mt-1">
                    <Amount
                      units={transfer.reserved_units}
                      asset={transfer.asset}
                    />
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Actual native fee</dt>
                  <dd className="mt-1">
                    {transfer.actual_fee_units === null ? (
                      "Not observed; not zero"
                    ) : (
                      <Amount
                        units={transfer.actual_fee_units}
                        asset={transfer.asset}
                      />
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">
                    Journal reconciliation
                  </dt>
                  <dd
                    className={`mt-1 ${transfer.reconciliation === "matched" ? "text-success" : "text-warning"}`}
                  >
                    {transfer.reconciliation === "matched"
                      ? "Matched in sample only"
                      : "Pending; not matched"}
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>
                <h3>Independent approval</h3>
              </CardTitle>
              <CardDescription>
                {transfer.approvals.recorded} of {transfer.approvals.required}{" "}
                illustrative records. Not a verified quorum.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm leading-relaxed text-muted-foreground">
                Policy epoch, grant expiry, signed grants and authority receipts
                are not supplied. This console cannot verify or create an
                approval.
              </p>
              <Button
                disabled
                variant="outline"
                className="h-11 w-full"
                aria-describedby="verifier-reason"
              >
                Open independent verifier
              </Button>
              <p
                id="verifier-reason"
                className="text-xs leading-relaxed text-muted-foreground"
              >
                Unavailable: requires trusted signed objects from a connected
                custody service and an independently distributed verifier.
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>
                <h3>Technical identifiers</h3>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="space-y-4 text-xs">
                <div>
                  <dt className="text-muted-foreground">Sample intent ID</dt>
                  <dd className="mt-1 font-mono break-all">{transfer.id}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">
                    Amount in base units
                  </dt>
                  <dd className="mt-1 font-mono break-all">
                    {transfer.amount_units}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">
                    Maximum fee in base units
                  </dt>
                  <dd className="mt-1 font-mono break-all">
                    {transfer.maximum_fee_units}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">
                    Verified transaction / candidate lineage
                  </dt>
                  <dd className="mt-1">Not supplied by this sample</dd>
                </div>
              </dl>
            </CardContent>
          </Card>
        </div>
      </div>
      <SampleFreshness treasury={treasury} />
    </div>
  );
}

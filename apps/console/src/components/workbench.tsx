"use client";

import { useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  ArrowUpRight,
  Copy,
  Download,
  LockKeyhole,
  Search,
} from "lucide-react";
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
import type { SampleTreasury } from "@/lib/sample-treasury";

function SearchRecords({ path, label }: { path: string; label: string }) {
  const query = useSearchParams().get("q") ?? "";
  return (
    <form action={path} className="flex items-end gap-3" method="get">
      <div className="min-w-0 flex-1 space-y-2 sm:max-w-md">
        <Label htmlFor="record-query">{label}</Label>
        <Input
          key={query}
          id="record-query"
          name="q"
          defaultValue={query}
          maxLength={160}
          className="h-11"
          placeholder="Search public sample records"
        />
      </div>
      <Button variant="outline" type="submit" className="h-11">
        <Search aria-hidden="true" />
        <span className="sr-only sm:not-sr-only">Search</span>
      </Button>
    </form>
  );
}

function EmptyRecords({ path }: { path: string }) {
  return (
    <div role="status" className="space-y-3 py-8">
      <h3 className="font-medium">No sample records match</h3>
      <p className="text-sm text-muted-foreground">
        Change the public reference or clear this search.
      </p>
      <Button asChild variant="outline">
        <Link href={path}>Clear search</Link>
      </Button>
    </div>
  );
}

export function FullAddress({ address }: { address: string }) {
  const [message, setMessage] = useState("");
  return (
    <div className="space-y-2">
      <code className="block text-sm break-all">{address}</code>
      <Button
        variant="outline"
        className="h-11 sm:h-9"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(address);
            setMessage(
              "Public example copied. Not an activated receiving address.",
            );
          } catch {
            setMessage(
              "Copy unavailable. Select the full public example above.",
            );
          }
        }}
      >
        <Copy aria-hidden="true" />
        Copy public example
      </Button>
      <p role="status" className="text-xs text-muted-foreground">
        {message}
      </p>
    </div>
  );
}

export function VaultsView({
  treasury,
  id,
}: {
  treasury: SampleTreasury;
  id?: string;
}) {
  const query = useSearchParams().get("q") ?? "";
  const vault = treasury.holdings.find((item) => item.id === id);
  const filtered = treasury.holdings.filter((item) =>
    `${item.vault} ${item.asset.network}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  if (vault) {
    const transfers = treasury.transfers.filter(
      (item) => item.vault === vault.vault,
    );
    return (
      <div className="space-y-6">
        <Button asChild variant="outline">
          <Link
            href={`/vaults${query ? `?q=${encodeURIComponent(query)}` : ""}`}
          >
            <ArrowLeft aria-hidden="true" />
            Back to vaults
          </Link>
        </Button>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="font-heading text-2xl">{vault.vault}</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              {vault.asset.network} · {vault.asset.network_identity}
            </p>
          </div>
          <Badge variant="outline">Control not verified</Badge>
        </div>
        <div className="grid gap-6 sm:grid-cols-3">
          {[
            ["Canonical", vault.canonical_units],
            ["Reserved incl. fee ceiling", vault.reserved_units],
            ["Available in sample", vault.available_units],
          ].map(([label, units]) => (
            <Card key={label}>
              <CardHeader>
                <CardDescription>{label}</CardDescription>
              </CardHeader>
              <CardContent>
                <Amount units={units} asset={vault.asset} />
              </CardContent>
            </Card>
          ))}
        </div>
        <div className="grid items-start gap-6 xl:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>
                <h3>Address & receiving readiness</h3>
              </CardTitle>
              <CardDescription>
                Public fixture only. Neither ownership nor monitoring is
                verified. Do not send funds to this example.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <FullAddress address={transfers[0].source_address} />
              <dl className="space-y-3 text-sm">
                {[
                  "Signing control",
                  "Address activation",
                  "Deposit monitoring",
                  "Recovery readiness",
                ].map((label) => (
                  <div
                    key={label}
                    className="flex flex-wrap justify-between gap-2 border-t pt-3"
                  >
                    <dt className="text-muted-foreground">{label}</dt>
                    <dd>Not verified</dd>
                  </div>
                ))}
              </dl>
              <Button
                disabled
                variant="outline"
                aria-describedby="receive-reason"
              >
                Activate receiving address
              </Button>
              <p id="receive-reason" className="text-xs text-muted-foreground">
                Requires independently verified address, monitored chain access
                and recovery readiness. No QR or deposit instruction is issued.
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>
                <h3>Related transfers</h3>
              </CardTitle>
              <CardDescription>
                Separate business requests; these are not verified on-chain
                observations.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="divide-y">
                {transfers.map((transfer) => (
                  <li key={transfer.id}>
                    <Link
                      href={`/transfers/${transfer.id}`}
                      className="flex items-center justify-between gap-4 py-4 text-sm hover:underline"
                    >
                      <div>
                        <p className="font-medium">{transfer.reference}</p>
                        <p className="mt-1 text-muted-foreground">
                          {transfer.state}
                        </p>
                      </div>
                      <ArrowUpRight
                        className="size-4 shrink-0"
                        aria-hidden="true"
                      />
                    </Link>
                  </li>
                ))}
              </ul>
              <Button asChild className="mt-5">
                <Link href={`/transfers/new?vault=${vault.id}`}>
                  Explore transfer review
                </Link>
              </Button>
            </CardContent>
          </Card>
        </div>
        <SampleFreshness treasury={treasury} />
      </div>
    );
  }
  return (
    <div className="space-y-6">
      <SearchRecords path="/vaults" label="Find a vault" />
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Sample vaults</h2>
          </CardTitle>
          <CardDescription>
            Purpose, network and exposure stay separate. Watch-only imports are
            not signing-controlled vaults.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {filtered.length > 0 && (
            <p className="mb-3 text-xs text-muted-foreground">
              Scroll the table horizontally to inspect every amount and control
              status.
            </p>
          )}
          {filtered.length ? (
            <Table aria-label="Sample vault holdings and control status">
              <TableCaption>
                Illustrative holdings, not spendable balances or controlled
                deposit accounts.
              </TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>Vault / network</TableHead>
                  <TableHead>Canonical</TableHead>
                  <TableHead>Reserved</TableHead>
                  <TableHead>Available</TableHead>
                  <TableHead>Control</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="min-w-52 whitespace-normal">
                      <Link
                        href={`/vaults/${item.id}${query ? `?q=${encodeURIComponent(query)}` : ""}`}
                        className="font-medium hover:underline"
                      >
                        {item.vault}
                      </Link>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {item.asset.network}
                      </p>
                    </TableCell>
                    <TableCell>
                      <Amount units={item.canonical_units} asset={item.asset} />
                    </TableCell>
                    <TableCell>
                      <Amount units={item.reserved_units} asset={item.asset} />
                    </TableCell>
                    <TableCell>
                      <Amount units={item.available_units} asset={item.asset} />
                    </TableCell>
                    <TableCell>Not verified</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyRecords path="/vaults" />
          )}
        </CardContent>
      </Card>
      <SampleFreshness treasury={treasury} />
    </div>
  );
}

export function ApprovalsView({ treasury }: { treasury: SampleTreasury }) {
  const query = useSearchParams().get("q") ?? "";
  const transfers = treasury.transfers.filter(
    (item) =>
      item.state === "AwaitingApproval" &&
      `${item.reference} ${item.vault} ${item.destination.name}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  return (
    <div className="space-y-6">
      <Alert>
        <LockKeyhole aria-hidden="true" />
        <AlertTitle>Independent approval, separate from the console</AlertTitle>
        <AlertDescription>
          No signed grants, trusted roots, policy epoch or expiry are supplied.
          Eligibility and quorum cannot be verified. Logging in would not grant
          approval authority.
        </AlertDescription>
      </Alert>
      <SearchRecords path="/approvals" label="Find an approval request" />
      {transfers.length ? (
        transfers.map((item) => (
          <Card key={item.id}>
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center justify-between gap-3">
                <h2>{item.reference}</h2>
                <Badge variant="outline">Awaiting approvals · sample</Badge>
              </CardTitle>
              <CardDescription>{item.purpose}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <dl className="grid gap-5 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-muted-foreground">Vault / network</dt>
                  <dd className="mt-2">
                    {item.vault} · {item.asset.network}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">
                    Amount / maximum native fee
                  </dt>
                  <dd className="mt-2">
                    <Amount units={item.amount_units} asset={item.asset} />
                    <span className="mx-2">/</span>
                    <Amount units={item.maximum_fee_units} asset={item.asset} />
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-muted-foreground">
                    Full destination · sample registry v
                    {item.destination.version}
                  </dt>
                  <dd className="mt-2">
                    <code className="break-all">
                      {item.destination.address}
                    </code>
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">
                    Illustrative approval records
                  </dt>
                  <dd className="mt-2">
                    {item.approvals.recorded} of {item.approvals.required} · not
                    a verified quorum
                  </dd>
                  <p className="mt-1 text-muted-foreground">
                    Expiry and approval eligibility not supplied
                  </p>
                </div>
              </dl>
              <div className="flex flex-wrap gap-3">
                <Button asChild variant="outline">
                  <Link href={`/transfers/${item.id}`}>Inspect request</Link>
                </Button>
                <Button disabled aria-describedby="approval-unavailable">
                  Open independent verifier
                </Button>
              </div>
              <p
                id="approval-unavailable"
                className="text-xs leading-relaxed text-muted-foreground"
              >
                Unavailable until a separately trusted client and signed objects
                are connected. No approve, reject or credential-signing action
                runs in this console.
              </p>
            </CardContent>
          </Card>
        ))
      ) : (
        <Card>
          <CardContent>
            <EmptyRecords path="/approvals" />
          </CardContent>
        </Card>
      )}
      <SampleFreshness treasury={treasury} />
    </div>
  );
}

export function DestinationsView({ treasury }: { treasury: SampleTreasury }) {
  const query = useSearchParams().get("q") ?? "";
  const destinations = treasury.transfers
    .filter(
      (item, index, all) =>
        all.findIndex(
          (other) =>
            other.asset.network === item.asset.network &&
            other.destination.address === item.destination.address &&
            other.destination.version === item.destination.version,
        ) === index,
    )
    .filter((item) =>
      `${item.destination.name} ${item.destination.address} ${item.asset.network}`
        .toLowerCase()
        .includes(query.toLowerCase()),
    );
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <SearchRecords path="/destinations" label="Find a destination" />
        <div className="space-y-2">
          <Button disabled aria-describedby="destination-reason">
            Request destination change
          </Button>
          <p id="destination-reason" className="text-xs text-muted-foreground">
            Requires governed registry and independent administrative approval.
          </p>
        </div>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Versioned destination references</h2>
          </CardTitle>
          <CardDescription>
            Names and versions come from transfer examples, not an active
            registry. No address is approved for use by this sample.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {destinations.length ? (
            <ul className="divide-y">
              {destinations.map((item) => (
                <li
                  key={`${item.asset.network}:${item.destination.version}`}
                  className="space-y-4 py-5 first:pt-0 last:pb-0"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <h3 className="font-medium">{item.destination.name}</h3>
                    <Badge variant="outline">Activation not verified</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {item.asset.network} · sample version{" "}
                    {item.destination.version} · ownership not verified
                  </p>
                  <FullAddress address={item.destination.address} />
                  <Link
                    className="inline-block text-sm underline underline-offset-4"
                    href={`/transfers/${item.id}`}
                  >
                    Inspect referencing transfer
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyRecords path="/destinations" />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export function OperationsView({
  treasury,
  caseId,
}: {
  treasury: SampleTreasury;
  caseId?: string;
}) {
  const query = useSearchParams().get("q") ?? "";
  const cases = treasury.transfers.filter(
    (item) =>
      item.state === "SubmissionUnknown" ||
      (item.state === "FinalizedSuccess" && item.reconciliation === "pending"),
  );
  const item = cases.find((record) => record.id === caseId);
  if (item)
    return (
      <div className="space-y-6">
        <Button asChild variant="outline">
          <Link
            href={`/operations${query ? `?q=${encodeURIComponent(query)}` : ""}`}
          >
            <ArrowLeft aria-hidden="true" />
            Back to operations
          </Link>
        </Button>
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>
                {item.state === "SubmissionUnknown"
                  ? "Submission acknowledgement missing"
                  : "Journal reconciliation pending"}
              </h2>
            </CardTitle>
            <CardDescription>
              {item.reference} · {item.vault} · illustrative case, not an
              incident ticket
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <dl className="grid gap-6 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">Affected principal</dt>
                <dd className="mt-2">
                  <Amount units={item.amount_units} asset={item.asset} />
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Reserved exposure</dt>
                <dd className="mt-2">
                  <Amount units={item.reserved_units} asset={item.asset} />
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">
                  Can a signature exist?
                </dt>
                <dd className="mt-2">
                  {item.state === "SubmissionUnknown"
                    ? "Yes. Issuance committed; outcome uncertain."
                    : "Issued in the scenario; chain finality is separate from accounting."}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">
                  Evidence / responsible role
                </dt>
                <dd className="mt-2">
                  Sample as of{" "}
                  <time dateTime={item.updated_at}>
                    {item.updated_at.replace("T", " ")}
                  </time>
                </dd>
                <p className="mt-1 text-muted-foreground">
                  No live evidence. Treasury operations with{" "}
                  {item.state === "SubmissionUnknown"
                    ? "broadcaster owner"
                    : "reconciler owner"}
                  ; no assignment recorded.
                </p>
              </div>
            </dl>
            <Alert>
              <AlertTitle>
                {item.state === "SubmissionUnknown"
                  ? "Keep funds reserved. No new payment or blind retry."
                  : "Do not mark the journal balanced manually."}
              </AlertTitle>
              <AlertDescription>
                {item.state === "SubmissionUnknown"
                  ? "Inspect retained issuance and the existing submission attempt. Identical-byte rebroadcast requires retained transaction bytes and backend support; neither is provided here."
                  : "Inspect canonical chain observations, journal entries and checkpoint lineage. A matched accounting outcome needs authoritative evidence, not a UI override."}
              </AlertDescription>
            </Alert>
            <div className="flex flex-wrap gap-3">
              <Button asChild>
                <Link href={`/transfers/${item.id}`}>
                  Inspect transfer & timeline
                </Link>
              </Button>
              <Button
                disabled
                variant="outline"
                aria-describedby="case-action-reason"
              >
                Check authoritative evidence
              </Button>
            </div>
            <p
              id="case-action-reason"
              className="text-xs text-muted-foreground"
            >
              Unavailable: no connected evidence service. Reloading only reloads
              historical fixtures; it does not resolve this case.
            </p>
          </CardContent>
        </Card>
        <SampleFreshness treasury={treasury} />
      </div>
    );
  const filtered = cases.filter((record) =>
    `${record.reference} ${record.vault} ${record.state}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  return (
    <div className="space-y-6">
      <SearchRecords path="/operations" label="Find an operational case" />
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Cases requiring investigation</h2>
          </CardTitle>
          <CardDescription>
            Uncertain issuance and journal mismatch need different evidence, not
            a universal Retry action.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {filtered.length ? (
            <ul className="divide-y">
              {filtered.map((record) => (
                <li key={record.id}>
                  <Link
                    href={`/cases/${record.id}${query ? `?q=${encodeURIComponent(query)}` : ""}`}
                    className="flex items-start justify-between gap-4 py-5 hover:underline"
                  >
                    <div className="space-y-2">
                      <h3 className="font-medium">
                        {record.state === "SubmissionUnknown"
                          ? "Submission uncertain"
                          : "Finalized; journal pending"}
                      </h3>
                      <p className="text-sm text-muted-foreground">
                        {record.reference} · {record.vault}
                      </p>
                      <Amount
                        units={record.amount_units}
                        asset={record.asset}
                      />
                    </div>
                    <ArrowUpRight
                      aria-hidden="true"
                      className="mt-1 size-4 shrink-0"
                    />
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyRecords path="/operations" />
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Funding & sweep workflows</h2>
          </CardTitle>
          <CardDescription>
            No workflow read model is connected. This sample does not invent
            deposits, child intents, spend caps or successful automated sweeps.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
            A connected workflow must expose its trigger/deduplication identity,
            child intents, settled dependencies, native spend allowance and
            pause reason. Resuming cannot raise a ceiling or bypass normal
            approval.
          </p>
          <Button disabled variant="outline" aria-describedby="workflow-reason">
            Configure funding or sweep
          </Button>
          <p id="workflow-reason" className="text-xs text-muted-foreground">
            Requires authenticated workflow API, scoped policy and independently
            approved configuration.
          </p>
        </CardContent>
      </Card>
      <SampleFreshness treasury={treasury} />
    </div>
  );
}

export function ActivityView({ treasury }: { treasury: SampleTreasury }) {
  const query = useSearchParams().get("q") ?? "";
  const events = treasury.transfers
    .flatMap((transfer) =>
      transfer.timeline.map((event) => ({
        ...event,
        transfer_id: transfer.id,
        reference: transfer.reference,
        vault: transfer.vault,
      })),
    )
    .sort((a, b) => b.time.localeCompare(a.time))
    .filter((event) =>
      `${event.reference} ${event.vault} ${event.title}`
        .toLowerCase()
        .includes(query.toLowerCase()),
    );
  function download() {
    const report = {
      schema_version: 1,
      kind: "illustrative_activity",
      source: treasury.source,
      as_of: treasury.as_of,
      signed: false,
      sequence_complete: false,
      filter: { q: query },
      events,
    };
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "oic-sample-activity.json";
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <SearchRecords
          path="/activity"
          label="Find activity by reference, vault or event"
        />
        <Button variant="outline" onClick={download}>
          <Download aria-hidden="true" />
          Download sample activity
        </Button>
      </div>
      <Alert>
        <AlertTitle>No verified event sequence or audit proof</AlertTitle>
        <AlertDescription>
          These are scenario notes sorted by time. Event sequence numbers,
          signed checkpoints, actor attribution and sequence-gap repair are
          unavailable. This export is incomplete and unsigned, not a custody
          audit.
        </AlertDescription>
      </Alert>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Sample activity</h2>
          </CardTitle>
          <CardDescription>
            {events.length} matching scenario notes. Chain finality and journal
            matching remain separate.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {events.length > 0 && (
            <p className="mb-3 text-xs text-muted-foreground">
              Scroll the table horizontally for event details and business
              references.
            </p>
          )}
          {events.length ? (
            <Table aria-label="Sample activity by time and business reference">
              <TableCaption>
                Historical illustrative notes only; no sequenced or signed event
                feed is connected.
              </TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>Time (UTC)</TableHead>
                  <TableHead>Event / context</TableHead>
                  <TableHead>Business reference</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((event) => (
                  <TableRow key={`${event.transfer_id}:${event.time}`}>
                    <TableCell className="align-top">
                      <time dateTime={event.time}>
                        {event.time.replace("T", " ").replace("Z", "")}
                      </time>
                    </TableCell>
                    <TableCell className="min-w-72 whitespace-normal">
                      <p className="font-medium">{event.title}</p>
                      <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                        {event.detail}
                      </p>
                    </TableCell>
                    <TableCell className="min-w-44 whitespace-normal">
                      <Link
                        className="underline underline-offset-4"
                        href={`/transfers/${event.transfer_id}`}
                      >
                        {event.reference}
                      </Link>
                      <p className="mt-2 text-xs text-muted-foreground">
                        {event.vault}
                      </p>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyRecords path="/activity" />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

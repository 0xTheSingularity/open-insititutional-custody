import Link from "next/link";
import { ArrowUpRight, CircleAlert, Clock3, LockKeyhole } from "lucide-react";
import { Button } from "@/components/ui/button";
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
import type { SampleTreasury } from "@/lib/sample-treasury";

export function CustodyUnavailable() {
  return (
    <Card>
      <CardHeader>
        <LockKeyhole
          className="size-5 text-muted-foreground"
          aria-hidden="true"
        />
        <CardTitle>
          <h2>Custody service not connected</h2>
        </CardTitle>
        <CardDescription>
          This local console stores watch-only addresses, not balances or
          transfers. Institution authentication, scoped read models and an
          independently trusted verifier must be connected before custody
          workflows are available.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Button asChild variant="outline" className="h-11">
          <Link href="/readiness">Inspect readiness requirements</Link>
        </Button>
      </CardContent>
    </Card>
  );
}

export function SampleFreshness({ treasury }: { treasury: SampleTreasury }) {
  return (
    <Alert>
      <Clock3 aria-hidden="true" />
      <AlertTitle>Historical sample, not live balances or evidence</AlertTitle>
      <AlertDescription>
        Illustrative snapshot{" "}
        <time dateTime={treasury.as_of}>
          {treasury.as_of.replace("T", " ").replace("Z", " UTC")}
        </time>
        , sequence {treasury.checkpoint_sequence}. No signed checkpoint, RPC
        observation or ownership proof has been verified. Reloading does not
        refresh these fixtures.
      </AlertDescription>
    </Alert>
  );
}

export function TreasuryView({ treasury }: { treasury: SampleTreasury }) {
  const tasks = treasury.transfers.filter(
    (transfer) =>
      transfer.state !== "FinalizedSuccess" ||
      transfer.reconciliation !== "matched",
  );
  return (
    <div className="space-y-8">
      <div className="grid items-start gap-8 xl:grid-cols-[minmax(0,1fr)_20rem]">
        <Card className="border-0 bg-transparent py-0">
          <CardHeader className="px-0">
            <CardTitle className="flex items-center justify-between gap-4">
              <h2>Needs attention</h2>
              <span className="font-sans text-xs font-normal tracking-normal text-muted-foreground">
                {tasks.length} sample tasks
              </span>
            </CardTitle>
            <CardDescription>
              Inspect the blocker before proposing another payment.
            </CardDescription>
          </CardHeader>
          <CardContent className="px-0">
            <ul className="divide-y overflow-hidden rounded-xl border">
              {tasks.map((transfer) => (
                <li key={transfer.id}>
                  <Link
                    href={`/transfers/${transfer.id}`}
                    className="group flex items-start gap-3 px-5 py-5 transition-colors hover:bg-muted/50 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring"
                  >
                    <CircleAlert
                      className="mt-1 size-4 shrink-0 text-warning"
                      aria-hidden="true"
                    />
                    <div className="min-w-0 flex-1">
                      <h3 className="text-sm font-medium group-hover:underline">
                        {transfer.state === "SubmissionUnknown"
                          ? "Submission acknowledgement missing"
                          : transfer.state === "AwaitingApproval"
                            ? "Independent approval required"
                            : "Reconciliation pending"}
                      </h3>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {transfer.reference} · {transfer.vault}
                      </p>
                      <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                        {transfer.state === "SubmissionUnknown"
                          ? "A signature may exist. Keep funds reserved; do not create a duplicate."
                          : transfer.state === "AwaitingApproval"
                            ? "The console cannot approve. Review requires independently verified objects."
                            : "Chain finality is recorded in the scenario; the journal has not matched yet."}
                      </p>
                    </div>
                    <ArrowUpRight
                      className="mt-1 size-4 shrink-0 text-muted-foreground"
                      aria-hidden="true"
                    />
                  </Link>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <LockKeyhole
              className="size-5 text-muted-foreground"
              aria-hidden="true"
            />
            <CardTitle>
              <h2>Read-only workspace</h2>
            </CardTitle>
            <CardDescription>
              Inspect historical examples, separate from your imported
              watch-only inventory.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button asChild className="h-11 w-full sm:h-9">
              <Link href="/transfers">Inspect sample transfers</Link>
            </Button>
            <Button
              disabled
              variant="outline"
              className="h-11 w-full sm:h-9"
              aria-describedby="overview-propose-reason"
            >
              Propose transfer
            </Button>
            <p
              id="overview-propose-reason"
              className="text-xs leading-relaxed text-muted-foreground"
            >
              Unavailable: no authenticated custody backend is connected. This
              sample cannot propose, approve, submit or cancel a payment.
            </p>
          </CardContent>
        </Card>
      </div>
      <SampleFreshness treasury={treasury} />
      <Card className="border-0 bg-transparent py-0">
        <CardHeader className="px-0">
          <CardTitle>
            <h2>Sample holdings by vault</h2>
          </CardTitle>
          <CardDescription>
            Canonical, reserved and available are separate quantities. Assets on
            different networks are never added into a portfolio total.
          </CardDescription>
        </CardHeader>
        <CardContent className="px-0">
          <p className="mb-3 text-xs text-muted-foreground lg:hidden">
            Scroll the table horizontally to inspect every amount.
          </p>
          <div className="overflow-hidden rounded-xl border">
            <Table>
              <TableCaption className="px-4 pb-4 text-left">
                Illustrative native assets only. Available amounts are not
                spendable funds.
              </TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>Vault / network</TableHead>
                  <TableHead>Canonical</TableHead>
                  <TableHead>Reserved incl. fee ceiling</TableHead>
                  <TableHead>Available</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {treasury.holdings.map((holding) => (
                  <TableRow key={`${holding.vault}:${holding.asset.network}`}>
                    <TableCell className="min-w-48 py-5 whitespace-normal">
                      <strong className="block font-medium">
                        {holding.vault}
                      </strong>
                      <span className="mt-1 block text-xs text-muted-foreground">
                        {holding.asset.network} · native {holding.asset.symbol}
                      </span>
                    </TableCell>
                    <TableCell className="min-w-40 whitespace-normal">
                      <Amount
                        units={holding.canonical_units}
                        asset={holding.asset}
                      />
                    </TableCell>
                    <TableCell className="min-w-44 whitespace-normal">
                      <Amount
                        units={holding.reserved_units}
                        asset={holding.asset}
                      />
                    </TableCell>
                    <TableCell className="min-w-48 whitespace-normal">
                      <Amount
                        units={holding.available_units}
                        asset={holding.asset}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  ArrowUpRight,
  Download,
  LockKeyhole,
  RotateCw,
  Search,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Amount } from "@/components/amount";
import { LocalTransferComposer } from "@/components/local-transfer-composer";
import { custodyRequest } from "@/lib/custody-client";
import {
  readCatalog,
  readIntentIds,
  readIntentRecord,
  readOperation,
  readStatus,
  type CustodyIntentRecord,
  type CustodyOperation,
  type LocalCatalog,
  type LocalStatus,
  checkpointView,
  lifecycleDisplay,
  liveApprovals,
  matchesQuery,
  needsApproval,
  requiredApprovals,
} from "@/lib/custody-model";

type Data = {
  catalog: LocalCatalog;
  status: LocalStatus;
  records: CustodyIntentRecord[];
  operations: Record<string, CustodyOperation>;
  readAt: string;
};
const preDispatch = new Set([
  "DRAFT",
  "BUILT",
  "VERIFIED",
  "POLICY_EVALUATED",
  "AWAITING_APPROVAL",
]);
const toneClass = {
  success: "border-success-border bg-success-surface text-success",
  attention: "border-warning-border bg-warning-surface text-warning",
  danger: "border-destructive/40 bg-destructive/10 text-destructive",
  neutral: "",
} as const;
function StateBadge({ state }: { state: string }) {
  const display = lifecycleDisplay[state as keyof typeof lifecycleDisplay];
  return (
    <Badge
      variant="outline"
      title={state}
      className={display ? toneClass[display.tone] : toneClass.attention}
    >
      {display ? display.label : state}
    </Badge>
  );
}
function DownloadLink({
  path,
  children,
  filename,
}: {
  path: string;
  children: React.ReactNode;
  filename: string;
}) {
  return (
    <Button asChild variant="outline" className="h-11">
      <a href={`/custody-api/v1/${path}`} download={filename}>
        <Download aria-hidden="true" />
        {children}
      </a>
    </Button>
  );
}

export function CustodyWorkspace({
  pathname,
  refreshKey,
  onConnection,
}: {
  pathname: string;
  refreshKey: number;
  onConnection: (connected: boolean) => void;
}) {
  const [data, setData] = useState<Data | null>(null);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [query, setQuery] = useState("");
  const flight = useRef(false);
  const reload = useCallback(async () => {
    if (flight.current) return;
    flight.current = true;
    setBusy(true);
    try {
      const catalog = readCatalog(await custodyRequest("catalog"));
      const status = readStatus(await custodyRequest("status"));
      const ids = readIntentIds(await custodyRequest("intents"));
      const records: CustodyIntentRecord[] = [];
      const operations: Record<string, CustodyOperation> = Object.create(null);
      // Bound concurrency while retaining every persisted intent. No requests
      // are dropped because an operation disappeared from a first-page list.
      for (let start = 0; start < ids.length; start += 8) {
        const page = await Promise.all(
          ids.slice(start, start + 8).map(async (id) => {
            const record = readIntentRecord(
              await custodyRequest(`intents/${encodeURIComponent(id)}`),
            );
            if (
              record.intent.intent_id !== id ||
              record.intent.institution_id !== catalog.institution_id
            )
              throw new Error(
                "Intent scope differs from the local catalog. Actions are paused.",
              );
            const family = record.built.candidate.operation_family_id;
            const operation = readOperation(
              await custodyRequest(`operations/${encodeURIComponent(family)}`),
            );
            if (operation.operation_family_id !== family)
              throw new Error(
                "Operation identity differs from its intent. Actions are paused.",
              );
            return { record, operation };
          }),
        );
        for (const item of page) {
          records.push(item.record);
          operations[item.record.intent.intent_id] = item.operation;
        }
      }
      setData({
        catalog,
        status,
        records: records.sort(
          (a, b) => b.intent.created_at - a.intent.created_at,
        ),
        operations,
        readAt: new Date().toISOString(),
      });
      setBlocked(false);
      setError("");
      onConnection(true);
    } catch (e) {
      setBlocked(true);
      setError(
        e instanceof Error ? e.message : "Custody state could not be loaded.",
      );
      onConnection(false);
    } finally {
      flight.current = false;
      setBusy(false);
    }
  }, [onConnection]);
  useEffect(() => {
    void reload();
  }, [reload, refreshKey]);

  async function act(
    record: CustodyIntentRecord,
    action: "submit" | "cancel" | "refresh",
  ) {
    if (flight.current || blocked) return;
    flight.current = true;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const path =
        action === "refresh"
          ? `operations/${encodeURIComponent(record.built.candidate.operation_family_id)}/refresh`
          : `intents/${encodeURIComponent(record.intent.intent_id)}/${action}`;
      await custodyRequest(path, { method: "POST" });
      setMessage(
        action === "submit"
          ? "Submission request recorded. This is not chain finality; inspect the operation state below."
          : action === "cancel"
            ? "Pre-dispatch cancellation recorded."
            : "Chain observation refreshed.",
      );
      flight.current = false;
      await reload();
    } catch (e) {
      setBlocked(true);
      setError(
        e instanceof Error
          ? e.message
          : "Outcome unknown. Inspect existing records before acting.",
      );
    } finally {
      flight.current = false;
      setBusy(false);
    }
  }

  if (!data)
    return (
      <Card role="status">
        <CardHeader>
          <LockKeyhole
            className="size-5 text-muted-foreground"
            aria-hidden="true"
          />
          <CardTitle>
            <h2>
              {error
                ? "Local custody connection unavailable"
                : "Loading local custody records…"}
            </h2>
          </CardTitle>
          <CardDescription>
            {error ||
              "Reading the enrolled catalog, reconciled holdings and persisted intents. No sample balances are used."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Use the local stack's private console.env handoff on the Next
            server. This is a scoped development operator, not institution
            login.
          </p>
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => void reload()}
          >
            <RotateCw aria-hidden="true" />
            Reload custody state
          </Button>
        </CardContent>
      </Card>
    );
  const { catalog, status, records, operations } = data;
  // Grant expiry is judged at the time this state was read, not render time.
  const nowSeconds = Math.floor(Date.parse(data.readAt) / 1000);
  const id = pathname.split("/")[2];
  const record = records.find((item) => item.intent.intent_id === id);
  const detail = pathname.startsWith("/transfers/") && id !== "new";
  const attention = records.filter(
    (item) =>
      item.dispatch !== "cancelled" &&
      ![
        "FINALIZED_SUCCESS",
        "FINALIZED_FAILURE",
        "ABORTED_BEFORE_ISSUANCE",
      ].includes(operations[item.intent.intent_id].lifecycle),
  );
  const isOverview = pathname === "/overview";
  const isVaults = pathname.startsWith("/vaults");
  const isTransfers =
    pathname === "/transfers" ||
    pathname === "/operations" ||
    pathname === "/approvals" ||
    pathname.startsWith("/cases/");

  return (
    <div className="space-y-6" aria-busy={busy}>
      <Alert>
        <ShieldCheck aria-hidden="true" />
        <AlertTitle>Connected to the local simulator stack</AlertTitle>
        <AlertDescription>
          {catalog.institution_id} · environment {catalog.environment_id}.
          Test-money proposals and submission only. Approval keys and simulator
          controls are outside this console. This is not production custody.
        </AlertDescription>
      </Alert>
      {error && (
        <Alert variant="destructive">
          <AlertTitle>Actions paused; last-known records below</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {message && (
        <Alert role="status">
          <AlertTitle>Request recorded</AlertTitle>
          <AlertDescription>{message}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
        <span>
          Last read{" "}
          <time dateTime={data.readAt}>
            {new Date(data.readAt).toLocaleTimeString()}
          </time>
          . Reload refreshes indexing and observations; it does not resubmit
          payments.
        </span>
        <Button
          variant="outline"
          size="sm"
          disabled={busy}
          onClick={() => void reload()}
        >
          <RotateCw aria-hidden="true" />
          Refresh custody state
        </Button>
      </div>

      {pathname === "/transfers/new" && (
        <LocalTransferComposer
          catalog={catalog}
          status={status}
          records={records}
          disabled={busy || blocked}
        />
      )}

      {(isOverview || isVaults) && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="font-heading text-2xl">
                {isVaults ? "Enrolled vault wallets" : "Reconciled holdings"}
              </h2>
              <p className="mt-2 text-sm text-muted-foreground">
                Settled, reserved and available are separate. Different networks
                are never summed.
              </p>
            </div>
            <Button asChild>
              <Link href="/transfers/new">
                New local transfer
                <ArrowUpRight aria-hidden="true" />
              </Link>
            </Button>
          </div>
          <div
            className="grid gap-4 xl:grid-cols-2"
            aria-label="Local custody holdings"
          >
            {catalog.wallets
              .filter((w) => !isVaults || !id || w.vault_id === id)
              .map((wallet) => {
                const balance = status.balances.find(
                  (b) => b.holdings.chain_wallet_id === wallet.chain_wallet_id,
                );
                const asset = catalog.assets.find(
                  (a) => a.asset_id === balance?.holdings.asset_id,
                );
                return (
                  <Card key={wallet.chain_wallet_id} className="min-w-0">
                    <CardHeader>
                      <CardTitle>
                        <h3>{wallet.chain_wallet_id}</h3>
                      </CardTitle>
                      <CardDescription>
                        {
                          catalog.vaults.find(
                            (v) => v.vault_id === wallet.vault_id,
                          )?.display_name
                        }{" "}
                        · {wallet.network_id}
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-5">
                      <code className="block text-xs break-all">
                        {wallet.address_display}
                      </code>
                      <dl className="grid gap-5 sm:grid-cols-2">
                        {(
                          [
                            "settled",
                            "reserved",
                            "available",
                            "pending_inbound",
                          ] as const
                        ).map((key) => (
                          <div key={key} className="min-w-0">
                            <dt className="text-xs text-muted-foreground capitalize">
                              {key.replaceAll("_", " ")}
                            </dt>
                            <dd className="mt-2">
                              {balance && asset ? (
                                <Amount
                                  units={balance.holdings[key]}
                                  asset={asset}
                                />
                              ) : (
                                "Unavailable"
                              )}
                            </dd>
                          </div>
                        ))}
                      </dl>
                      <p className="border-t pt-4 text-xs text-muted-foreground">
                        {wallet.active
                          ? "Active in local enrollment"
                          : "Inactive"}{" "}
                        · Actual simulator journal, not mainnet funds or policy
                        allowance.
                      </p>
                    </CardContent>
                  </Card>
                );
              })}
          </div>
          {isOverview && (
            <Card>
              <CardHeader>
                <CardTitle>
                  <h2>Needs attention</h2>
                </CardTitle>
                <CardDescription>
                  {attention.length} persisted operations require inspection. Do
                  not replace uncertain payments.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="divide-y">
                  {attention.length ? (
                    attention.map((item) => (
                      <Link
                        key={item.intent.intent_id}
                        href={`/transfers/${encodeURIComponent(item.intent.intent_id)}`}
                        className="flex flex-wrap items-center justify-between gap-3 py-4"
                      >
                        <span className="min-w-0 break-all">
                          {item.intent.external_reference}
                        </span>
                        <StateBadge
                          state={operations[item.intent.intent_id].lifecycle}
                        />
                      </Link>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      No pending operations in the current records.
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
          <Card>
            <CardHeader>
              <CardTitle>
                <h2>Development boundaries</h2>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="space-y-3 text-sm">
                {Object.entries(catalog.backend_limits).map(([key, value]) => (
                  <div key={key}>
                    <dt className="font-medium capitalize">{key}</dt>
                    <dd className="mt-1 text-muted-foreground">{value}</dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>
        </>
      )}

      {isTransfers && (
        <>
          {pathname === "/approvals" && (
            <Alert>
              <LockKeyhole aria-hidden="true" />
              <AlertTitle>
                Approval happens in the independent verifier
              </AlertTitle>
              <AlertDescription>
                Open a transfer and download its approval package. Review with
                your separately trusted oic-approve client and submit its signed
                grant using the separate approval capability. No approval key,
                grant upload or approval vote is accepted here.
              </AlertDescription>
            </Alert>
          )}
          <Card>
            <CardHeader className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <CardTitle>
                  <h2>
                    {pathname === "/approvals"
                      ? "Independent approval queue"
                      : "Persisted local transfers"}
                  </h2>
                </CardTitle>
                <CardDescription className="mt-2">
                  One immutable intent per request. Submission, finality and
                  reconciliation remain separate.
                </CardDescription>
              </div>
              <Button asChild variant="outline">
                <Link href="/transfers/new">New local transfer</Link>
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex max-w-md items-center gap-2">
                <Search aria-hidden="true" className="size-4 text-muted-foreground" />
                <Input
                  aria-label="Search transfers by reference, intent, vault, destination, asset, or transaction"
                  placeholder="Search reference, intent, vault, destination, tx"
                  value={query}
                  maxLength={160}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </div>
              <Table aria-label="Persisted local transfers">
                <TableHeader>
                  <TableRow>
                    <TableHead>Reference / intent</TableHead>
                    <TableHead>Amount</TableHead>
                    <TableHead>Recorded grants</TableHead>
                    <TableHead>Chain lifecycle</TableHead>
                    <TableHead>Dispatch</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {records
                    .filter((item) => matchesQuery(item, query))
                    .filter(
                      (item) =>
                        pathname !== "/approvals" ||
                        needsApproval(
                          item,
                          operations[item.intent.intent_id].lifecycle,
                        ),
                    )
                    .map((item) => (
                      <TableRow key={item.intent.intent_id}>
                        <TableCell className="min-w-52">
                          <Link
                            className="font-medium underline underline-offset-4"
                            href={`/transfers/${encodeURIComponent(item.intent.intent_id)}`}
                          >
                            {item.intent.external_reference}
                          </Link>
                          <p className="mt-1 max-w-72 font-mono text-xs break-all text-muted-foreground">
                            {item.intent.intent_id}
                          </p>
                        </TableCell>
                        <TableCell className="min-w-40">
                          <Amount
                            units={
                              item.intent.operation.asset_transfer
                                .amount_base_units
                            }
                            asset={item.built.package.asset}
                          />
                        </TableCell>
                        <TableCell>
                          {liveApprovals(item, nowSeconds)} unexpired of{" "}
                          {requiredApprovals(item) ?? "no matching rule"} ·
                          not a quorum assertion
                        </TableCell>
                        <TableCell>
                          <StateBadge
                            state={operations[item.intent.intent_id].lifecycle}
                          />
                        </TableCell>
                        <TableCell>{item.dispatch}</TableCell>
                      </TableRow>
                    ))}
                </TableBody>
                <TableCaption>
                  Records are backend observations. Recorded grants can be
                  expired or inapplicable; the backend re-evaluates
                  authorization on submit.
                </TableCaption>
              </Table>
              {!records.length && (
                <p className="py-4 text-sm text-muted-foreground">
                  No transfers have been created in this installation.
                </p>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {detail &&
        (record ? (
          <TransferDetail
            record={record}
            operation={operations[record.intent.intent_id]}
            disabled={busy || blocked}
            onAction={(action) => void act(record, action)}
          />
        ) : (
          <Alert>
            <AlertTitle>Transfer record unavailable</AlertTitle>
            <AlertDescription>
              No readable persisted record matches this ID. A missing record is
              not proof that an earlier submission had no effect. Inspect the
              local API and operation evidence before creating a replacement.
            </AlertDescription>
          </Alert>
        ))}

      {pathname === "/destinations" && (
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>Enrolled local destinations</h2>
            </CardTitle>
            <CardDescription>
              Backend registry data. Approval independently verifies the
              version, address and administrative signatures.
            </CardDescription>
          </CardHeader>
          <CardContent className="divide-y">
            {catalog.destinations.map((destination) => (
              <div
                className="space-y-2 py-5"
                key={`${destination.destination_id}:${destination.version}`}
              >
                <p className="font-medium">
                  {destination.display_name}{" "}
                  <Badge variant="outline">v{destination.version}</Badge>
                </p>
                <p className="text-xs text-muted-foreground">
                  {destination.network_id} · {destination.destination_id}
                </p>
                <code className="block text-sm break-all">
                  {destination.address_display}
                </code>
                <p className="text-xs text-muted-foreground">
                  Allowed assets:{" "}
                  {destination.allowed_assets.join(", ") ||
                    "All enrolled assets on this network"}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {(pathname === "/activity" ||
        pathname === "/operations" ||
        isOverview) && (
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>Reconciliation and audit evidence</h2>
            </CardTitle>
            <CardDescription>
              Latest chain-versus-journal checkpoints reported by the service.
              Signatures are not independently verified in this browser.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="grid gap-4 lg:grid-cols-2">
              {status.checkpoints.map((checkpoint) => {
                const body = checkpoint.body;
                const view = checkpointView(body, nowSeconds);
                return (
                  <div
                    className="space-y-2 border-l-2 pl-4"
                    key={body.checkpoint_id}
                  >
                    <p className="text-sm font-medium">
                      {body.chain_profile_id}
                    </p>
                    <Badge variant="outline" className={toneClass[view.tone]}>
                      {view.label}
                    </Badge>
                    <p className="text-xs text-muted-foreground">
                      Taken {view.ageSeconds}s before this read · checkpoint{" "}
                      {body.checkpoint_id} · journal sequence{" "}
                      {body.journal_sequence} · {body.state.commitment} height{" "}
                      {body.state.height}
                    </p>
                    <code className="block text-xs break-all">
                      {body.state.hash}
                    </code>
                  </div>
                );
              })}
            </div>
            <div className="flex flex-wrap gap-3">
              <DownloadLink
                path="export"
                filename="oic-local-custody-export.json"
              >
                Download custody export
              </DownloadLink>
              <DownloadLink
                path="events?after=0&limit=1000"
                filename="oic-local-first-1000-events.json"
              >
                Download first 1,000 events
              </DownloadLink>
            </div>
            <p className="text-xs leading-relaxed text-muted-foreground">
              The export contains the operational journal and authority
              checkpoint, not a cross-store atomic backup. Download individual
              operation evidence for reconstruction. Event replay is paginated
              and signatures need separately pinned verification keys; this
              browser does not claim a complete verified event stream.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function TransferDetail({
  record,
  operation,
  disabled,
  onAction,
}: {
  record: CustodyIntentRecord;
  operation: CustodyOperation;
  disabled: boolean;
  onAction: (action: "submit" | "cancel" | "refresh") => void;
}) {
  const { intent, built } = record;
  const required = requiredApprovals(record);
  const canDispatch =
    record.dispatch === "ready" &&
    record.issuance === null &&
    preDispatch.has(operation.lifecycle);
  const uncertain =
    [
      "ISSUANCE_UNKNOWN",
      "SUBMISSION_UNKNOWN",
      "ISSUANCE_COMMITTED",
      "SIGNING",
      "SIGNATURE_OBSERVED",
    ].includes(operation.lifecycle) || record.dispatch === "dispatching";
  const family = built.candidate.operation_family_id;
  return (
    <div className="space-y-6">
      <Button asChild variant="outline">
        <Link href="/transfers">
          <ArrowLeft aria-hidden="true" />
          Back to transfers
        </Link>
      </Button>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2 className="break-words">{intent.external_reference}</h2>
          </CardTitle>
          <CardDescription className="break-all">
            {intent.intent_id}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex flex-wrap items-center gap-3">
            <StateBadge state={operation.lifecycle} />
            <p className="mt-1 text-xs text-muted-foreground">
              <span className="font-mono">{operation.lifecycle}</span>
              {" · "}
              {lifecycleDisplay[operation.lifecycle].action}
            </p>
            <Badge variant="outline">Dispatch: {record.dispatch}</Badge>
            {operation.issuance && (
              <Badge variant="outline">
                Coordinator: {lifecycleDisplay[operation.issuance.lifecycle].label}
              </Badge>
            )}
            {record.last_error && (
              <Badge variant="outline">{record.last_error.code}</Badge>
            )}
          </div>
          {uncertain && (
            <Alert className="border-warning-border bg-warning-surface">
              <AlertTitle>A signature or chain effect may exist</AlertTitle>
              <AlertDescription>
                Keep principal and maximum fee exposure reserved. Do not cancel,
                issue again, or create a replacement payment. Inspect this
                operation's evidence and chain observations.
              </AlertDescription>
            </Alert>
          )}
          <dl className="grid gap-6 text-sm sm:grid-cols-2">
            {[
              [
                "Institution / environment",
                `${intent.institution_id} / ${intent.environment_id}`,
              ],
              [
                "Source wallet / network",
                `${intent.chain_wallet_id} / ${built.package.wallet.network_id}`,
              ],
              ["Full source address", built.package.wallet.address_display],
              [
                "Full beneficiary address",
                built.package.destination.address_display,
              ],
              [
                "Destination / registry version",
                `${intent.operation.asset_transfer.destination_id} / v${intent.operation.asset_transfer.destination_version}`,
              ],
              [
                "Policy binding",
                `${built.package.policy.policy_id} / epoch ${built.package.policy.policy_epoch}`,
              ],
              [
                "Approval mode / purpose",
                `${intent.constraints.approval_mode} / ${intent.purpose}`,
              ],
              ["Operation family", family],
            ].map(([label, value]) => (
              <div className="min-w-0" key={label}>
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="mt-2 break-all">{value}</dd>
              </div>
            ))}
            <div>
              <dt className="text-muted-foreground">Exact native amount</dt>
              <dd className="mt-2">
                <Amount
                  units={intent.operation.asset_transfer.amount_base_units}
                  asset={built.package.asset}
                />
              </dd>
              <p className="mt-1 font-mono text-xs break-all">
                {intent.operation.asset_transfer.amount_base_units} base units
              </p>
            </div>
            <div>
              <dt className="text-muted-foreground">Maximum network fee</dt>
              <dd className="mt-2">
                <Amount
                  units={intent.constraints.max_network_fee_base_units}
                  asset={built.package.asset}
                />
              </dd>
              <p className="mt-1 text-xs text-muted-foreground">
                Ceiling, not actual fee or a guarantee of feasibility.
              </p>
            </div>
          </dl>
          <div className="space-y-3 border-t pt-5">
            <h3 className="font-medium">Independent approval records</h3>
            <p className="text-sm">
              {required === null
                ? "No policy rule matches this transfer; the custody service will deny it."
                : `Policy requires ${required} independent approval${required === 1 ? "" : "s"}; ${record.approvals.length} recorded.`}
            </p>
            {record.approvals.length ? (
              record.approvals.map((grant, index) => (
                <p
                  className="text-sm break-all"
                  key={`${grant.body.approver_credential_id}:${index}`}
                >
                  {grant.body.approver_credential_id} · expires{" "}
                  {new Date(grant.body.expires_at * 1000).toLocaleString()}
                </p>
              ))
            ) : (
              <p className="text-sm text-muted-foreground">
                No signed grants recorded. Download the package and review it
                outside this console.
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              Recorded grants are not a claim of satisfied quorum. The API and
              signers verify scope, expiry, policy and signatures.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <DownloadLink
              path={`intents/${encodeURIComponent(intent.intent_id)}/preview`}
              filename={`${intent.intent_id}.package.json`}
            >
              Download approval package
            </DownloadLink>
            <DownloadLink
              path={`operations/${encodeURIComponent(family)}/evidence`}
              filename={`${intent.intent_id}.evidence.json`}
            >
              Download operation evidence
            </DownloadLink>
          </div>
          <Alert>
            <LockKeyhole aria-hidden="true" />
            <AlertTitle>The console cannot approve this request</AlertTitle>
            <AlertDescription>
              Use the separately trusted oic-approve client and its encrypted
              credential. The separate approval bearer posts the signed grant
              directly to the custody API. Then refresh this page. Never enter
              an approval passphrase or key here.
            </AlertDescription>
          </Alert>
          <div className="flex flex-wrap gap-3">
            <Button
              disabled={
                disabled || !canDispatch || record.approvals.length === 0
              }
              onClick={() => onAction("submit")}
            >
              Request local submission
            </Button>
            <Button
              variant="outline"
              disabled={disabled || (!record.issuance && !uncertain)}
              onClick={() => onAction("refresh")}
            >
              Refresh chain observation
            </Button>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" disabled={disabled || !canDispatch}>
                  Cancel before dispatch
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    Cancel this unsubmitted intent?
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    This requests pre-dispatch cancellation only. It cannot
                    revoke a signature or stop a payment already released. The
                    backend rejects cancellation if dispatch has started.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Keep intent</AlertDialogCancel>
                  <AlertDialogAction onClick={() => onAction("cancel")}>
                    Confirm cancellation
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Submission success records an issuance/broadcast attempt, not
            inclusion or finality. The console never resubmits signed or
            uncertain operations. A new candidate may be required if evidence or
            a Solana blockhash expires; do not bypass the independent approval
            flow.
          </p>
          {record.issuance && (
            <p className="text-sm break-all">
              Native transaction ID:{" "}
              <code>{record.issuance.signed.signed.chain_tx_id}</code>
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

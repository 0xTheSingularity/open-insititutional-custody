"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, Download, List, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
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
import type { Snapshot, Preview } from "@/lib/contracts";

const example =
  "network,address,label\nethereum-sepolia,0x52908400098527886E0F7030069857D2E4169EE7,Example EVM address\nsolana-devnet,11111111111111111111111111111111,Example Solana system address";
const networks = [
  "ethereum-mainnet",
  "ethereum-sepolia",
  "solana-mainnet",
  "solana-devnet",
];

export function InventoryView({
  snapshot,
  disabled,
  onPreview,
  onSave,
}: {
  snapshot: Snapshot;
  disabled: boolean;
  onPreview: (csv: string) => Promise<Preview | undefined>;
  onSave: (csv: string) => Promise<Snapshot | undefined>;
}) {
  const [csv, setCsv] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [filter, setFilter] = useState("");
  const [fileError, setFileError] = useState("");
  const [reading, setReading] = useState(false);
  const { setup } = snapshot;
  const demo = snapshot.mode === "demo";
  const filtered = setup.inventory.filter((row) =>
    `${row.label} ${row.network} ${row.address}`
      .toLowerCase()
      .includes(filter.toLowerCase()),
  );
  useEffect(() => setPreview(null), [setup.revision]);

  if (!setup.workspace_name)
    return (
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Create a test workspace first.</h2>
          </CardTitle>
          <CardDescription>
            Your inventory needs a named local environment. This does not create
            signing authority.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild className="h-11">
            <Link href="/setup">Create test workspace</Link>
          </Button>
        </CardContent>
      </Card>
    );

  return (
    <div className="space-y-6">
      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.65fr)_minmax(240px,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center justify-between gap-3">
              <h2>
                {demo ? "Preview public addresses" : "Import public addresses"}
              </h2>
              <Badge variant="secondary">Watch-only</Badge>
            </CardTitle>
            <CardDescription>
              No seed phrases, private keys, API credentials or source policies.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                void onPreview(csv).then((result) => {
                  if (result) setPreview(result);
                });
              }}
            >
              <div className="space-y-2">
                <Label htmlFor="address-csv">Public-address CSV</Label>
                <Textarea
                  id="address-csv"
                  className="min-h-48 font-mono text-sm"
                  value={csv}
                  onChange={(event) => {
                    setCsv(event.target.value);
                    setPreview(null);
                  }}
                  placeholder={
                    "network,address,label\nethereum-sepolia,0x…,Treasury test"
                  }
                  required
                  disabled={disabled || reading}
                  spellCheck={false}
                  aria-describedby="csv-help"
                />
                <p
                  id="csv-help"
                  className="text-xs leading-relaxed text-muted-foreground"
                >
                  Up to 500 rows / 128 KiB request. Quote labels containing
                  commas.{" "}
                  {demo
                    ? "Preview only; saving is disabled in this demo."
                    : "Preview is temporary until you explicitly save valid rows."}
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="csv-file">Or choose a CSV file</Label>
                <Input
                  id="csv-file"
                  type="file"
                  accept=".csv,text/csv"
                  className="h-11 pt-2"
                  disabled={disabled || reading}
                  onChange={async (event) => {
                    const file = event.target.files?.[0];
                    event.target.value = "";
                    if (!file) return;
                    if (file.size > 120000) {
                      setFileError("Choose a CSV smaller than 120 KB.");
                      return;
                    }
                    setReading(true);
                    setFileError("");
                    try {
                      setCsv(await file.text());
                      setPreview(null);
                    } catch {
                      setFileError(
                        "Could not read this file. Choose a readable public-address CSV.",
                      );
                    } finally {
                      setReading(false);
                    }
                  }}
                />
              </div>
              {fileError && (
                <Alert variant="destructive">
                  <AlertDescription>{fileError}</AlertDescription>
                </Alert>
              )}
              <div className="flex flex-wrap gap-3">
                <Button
                  type="submit"
                  className="h-11"
                  disabled={disabled || reading || !csv.trim()}
                >
                  Preview inventory
                  <ArrowRight aria-hidden="true" />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  className="h-11"
                  disabled={disabled || reading}
                  onClick={() => {
                    setCsv(example);
                    setPreview(null);
                  }}
                >
                  Use public test examples
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
        <aside className="space-y-6">
          <Alert>
            <ShieldCheck aria-hidden="true" />
            <AlertTitle>
              {demo
                ? "Custody stays separate."
                : "Your custodian keeps control."}
            </AlertTitle>
            <AlertDescription>
              {demo
                ? "This sample shows public examples only."
                : "This import saves public identifiers only."}{" "}
              It does not query chains, verify ownership, activate receiving
              addresses or move funds.
            </AlertDescription>
          </Alert>
          <Card>
            <CardHeader>
              <CardTitle>
                <h2>Supported network identifiers</h2>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 font-mono text-sm">
                {networks.map((network) => (
                  <li key={network}>{network}</li>
                ))}
              </ul>
              <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
                A valid address cannot prove which network you intended. Confirm
                the network with your source records.
              </p>
            </CardContent>
          </Card>
        </aside>
      </div>
      {preview && (
        <Card id="import-preview">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <h2>Review before saving</h2>
              <Badge variant="secondary">Not saved</Badge>
            </CardTitle>
            <CardDescription>
              <strong>{preview.importable} new valid addresses</strong>{" "}
              {demo
                ? "pass syntax checks. Saving is disabled in this demo."
                : "can be saved."}{" "}
              {preview.excluded} excluded: duplicate, invalid or unsupported
              rows are not imported.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <p className="text-xs text-muted-foreground lg:hidden">
              Scroll the table horizontally to inspect every column.
            </p>
            <div>
              <Table aria-label="Import preview">
                <TableCaption className="sr-only">
                  Public-address import validation results
                </TableCaption>
                <TableHeader>
                  <TableRow>
                    <TableHead>CSV row</TableHead>
                    <TableHead>Account / full address</TableHead>
                    <TableHead>Network</TableHead>
                    <TableHead>Result</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {preview.rows.map((row) => (
                    <TableRow key={row.row}>
                      <TableCell className="align-top">{row.row}</TableCell>
                      <TableCell className="min-w-52 align-top whitespace-normal">
                        <strong className="block">
                          {row.label || "Unlabeled address"}
                        </strong>
                        <code className="mt-1 block max-w-96 text-xs break-all">
                          {row.address}
                        </code>
                      </TableCell>
                      <TableCell className="align-top">{row.network}</TableCell>
                      <TableCell className="min-w-56 align-top whitespace-normal">
                        <Badge
                          variant="outline"
                          className={
                            row.status === "valid"
                              ? "text-success"
                              : "text-warning"
                          }
                        >
                          {row.status === "valid" ? "Valid syntax" : row.status}
                        </Badge>
                        <p className="mt-2 max-w-xs text-xs text-muted-foreground">
                          {row.reason}
                        </p>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="flex flex-wrap items-center gap-4">
              <Button
                className="h-11"
                disabled={disabled || !preview.importable || demo}
                onClick={async () => {
                  if (await onSave(csv)) {
                    setCsv("");
                    setPreview(null);
                  }
                }}
              >
                {demo
                  ? "Saving unavailable in public demo"
                  : `Save ${preview.importable} valid addresses`}
              </Button>
              <span className="text-xs text-muted-foreground">
                {demo
                  ? "This preview is temporary. No data is saved."
                  : "Excluded rows remain with your source system."}
              </span>
            </div>
          </CardContent>
        </Card>
      )}
      <Card id="saved-inventory">
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center justify-between gap-3">
            <h2>
              {demo ? "Sample inventory" : "Saved inventory"}{" "}
              <Badge variant="secondary">{setup.inventory.length}</Badge>
            </h2>
            <Button asChild variant="outline" className="h-11">
              <a href="/console-api/v1/export" download>
                <Download aria-hidden="true" />
                Export inventory
              </a>
            </Button>
          </CardTitle>
          <CardDescription>
            Public identifiers only. Balances and ownership are not verified.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {setup.inventory.length ? (
            <>
              <Label className="sr-only" htmlFor="inventory-filter">
                {demo ? "Filter sample inventory" : "Filter saved inventory"}
              </Label>
              <Input
                id="inventory-filter"
                className="h-11 max-w-sm"
                placeholder="Filter by label, network or full address"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              />
              <p className="text-xs text-muted-foreground lg:hidden">
                Scroll the table horizontally to inspect every column.
              </p>
              <div>
                <Table
                  aria-label={
                    demo ? "Sample public addresses" : "Saved public addresses"
                  }
                >
                  <TableCaption className="sr-only">
                    {demo
                      ? "Sample watch-only public addresses"
                      : "Saved watch-only public addresses"}
                  </TableCaption>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Account / full address</TableHead>
                      <TableHead>Network</TableHead>
                      <TableHead>Control</TableHead>
                      <TableHead>Balance</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.map((row) => (
                      <TableRow key={`${row.network}:${row.address}`}>
                        <TableCell className="min-w-56 py-4 whitespace-normal">
                          <strong>{row.label || "Unlabeled address"}</strong>
                          <code className="mt-1 block max-w-96 text-xs break-all">
                            {row.address}
                          </code>
                          <span className="mt-1 block text-xs text-muted-foreground">
                            {demo
                              ? "Public example; not an imported account"
                              : `Imported ${new Date(row.imported_at * 1000).toLocaleString()}`}
                          </span>
                        </TableCell>
                        <TableCell>{row.network}</TableCell>
                        <TableCell>
                          <Badge variant="secondary">Watch-only</Badge>
                          <span className="mt-2 block text-xs text-muted-foreground">
                            Ownership unverified
                          </span>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          Not observed
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {!filtered.length && (
                  <p className="p-5 text-sm text-muted-foreground">
                    No {demo ? "sample" : "saved"} addresses match this filter.
                  </p>
                )}
              </div>
            </>
          ) : (
            <div className="py-8 text-center">
              <List
                className="mx-auto mb-4 size-7 text-muted-foreground"
                aria-hidden="true"
              />
              <h3 className="font-medium">No addresses saved yet.</h3>
              <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">
                Preview a CSV above, inspect every excluded row, then save the
                valid addresses.
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

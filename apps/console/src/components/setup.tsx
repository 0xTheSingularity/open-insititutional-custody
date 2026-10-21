"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowRight, Check, LockKeyhole } from "lucide-react";
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
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { cn } from "@/lib/utils";
import type { Snapshot } from "@/lib/contracts";

export function SetupView({
  snapshot,
  disabled,
  onCreate,
}: {
  snapshot: Snapshot;
  disabled: boolean;
  onCreate: (name: string) => Promise<Snapshot | undefined>;
}) {
  const [name, setName] = useState("");
  const { setup, preflight } = snapshot;
  const steps = [
    {
      title: "Local preflight",
      detail: "Service and durable state",
      complete: true,
      href: "/setup",
    },
    {
      title: "Test workspace",
      detail: setup.workspace_name ?? "Name your local environment",
      complete: Boolean(setup.workspace_name),
      href: "/setup",
    },
    {
      title: "Read-only inventory",
      detail: setup.inventory.length
        ? `${setup.inventory.length} public addresses saved`
        : "Observe existing addresses",
      complete: setup.inventory.length > 0,
      href: "/inventory",
    },
    {
      title: "Local test transfer",
      detail: "Awaiting custody API integration",
      complete: false,
      href: null,
    },
    {
      title: "Production readiness",
      detail: "Required controls not verified",
      complete: false,
      href: "/readiness",
    },
  ];
  return (
    <div className="grid items-start gap-6 lg:grid-cols-[minmax(260px,.85fr)_minmax(0,1.5fr)]">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <h2>Your setup</h2>
            <span className="text-sm font-normal text-muted-foreground">
              {steps.filter((step) => step.complete).length} of 5
            </span>
          </CardTitle>
          <CardDescription>Progress is saved on this machine.</CardDescription>
        </CardHeader>
        <CardContent>
          <ol className="space-y-6 py-3">
            {steps.map((step, index) => (
              <li key={step.title} className="flex items-start gap-3">
                <span
                  className={cn(
                    "flex size-8 shrink-0 items-center justify-center rounded-full border text-xs text-muted-foreground",
                    step.complete && "border-success bg-success text-white",
                  )}
                >
                  {step.complete ? (
                    <Check className="size-4" aria-label="Complete" />
                  ) : (
                    index + 1
                  )}
                </span>
                <div className="min-w-0 flex-1">
                  <span className="text-sm font-medium">
                    {step.href ? (
                      <Link href={step.href} className="hover:underline">
                        {step.title}
                      </Link>
                    ) : (
                      step.title
                    )}
                  </span>
                  <span className="mt-1 block text-xs text-muted-foreground break-words">
                    {step.detail}
                  </span>
                </div>
                {!step.href && <Badge variant="outline">Blocked</Badge>}
              </li>
            ))}
          </ol>
          <p className="mt-5 border-t pt-4 text-xs leading-relaxed text-muted-foreground">
            No funds have moved. Public-address imports do not enroll an
            identity or approval credential.
          </p>
        </CardContent>
      </Card>
      <div className="space-y-6">
        {!setup.workspace_name ? (
          <Card>
            <CardHeader>
              <CardDescription>Test workspace</CardDescription>
              <CardTitle>
                <h2 className="text-xl">Give your test environment a name.</h2>
              </CardTitle>
              <CardDescription>
                Keep this trial separate from your institution’s production
                authority. No account, seed phrase or approval key is needed.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form
                className="space-y-4"
                onSubmit={(event) => {
                  event.preventDefault();
                  void onCreate(name);
                }}
              >
                <div className="space-y-2">
                  <Label htmlFor="workspace-name">Workspace name</Label>
                  <Input
                    id="workspace-name"
                    autoComplete="off"
                    required
                    maxLength={80}
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    placeholder="e.g. Treasury evaluation"
                    disabled={disabled}
                    className="h-11"
                    aria-describedby="workspace-help"
                  />
                  <p
                    id="workspace-help"
                    className="text-xs text-muted-foreground"
                  >
                    A local label, not an institution login or administrative
                    role.
                  </p>
                </div>
                <Button type="submit" disabled={disabled} className="h-11">
                  Create test workspace
                  <ArrowRight aria-hidden="true" />
                </Button>
              </form>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardDescription>
                {setup.inventory.length
                  ? "Your next milestone"
                  : "Next: read-only discovery"}
              </CardDescription>
              <CardTitle>
                <h2 className="max-w-sm text-2xl leading-tight tracking-tight">
                  {setup.inventory.length
                    ? "The inventory is saved. Signing stays separate."
                    : "Bring your public addresses. Nothing else."}
                </h2>
              </CardTitle>
              <CardDescription>
                {setup.inventory.length
                  ? "The local money loop is blocked until its API and verifier are connected. Your source custodian retains control."
                  : "Preview a CSV of existing addresses. Inspect duplicate, invalid and unsupported rows before you save."}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button asChild className="h-11">
                <Link href="/inventory">
                  {setup.inventory.length
                    ? "Open saved inventory"
                    : "Preview address inventory"}
                  <ArrowRight aria-hidden="true" />
                </Link>
              </Button>
            </CardContent>
          </Card>
        )}
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center justify-between gap-3">
              <h2>Local preflight</h2>
              <Badge variant="outline" className="text-success">
                Service reached
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="divide-y text-sm">
              {[
                ["Platform", `${preflight.os} / ${preflight.architecture}`],
                ["Console version", preflight.version],
                ["State storage", "Durable write completed"],
                [
                  "Distribution",
                  "Source build; release signature not verified",
                ],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className="flex flex-wrap justify-between gap-2 py-3"
                >
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="max-w-64 sm:text-right">{value}</dd>
                </div>
              ))}
            </dl>
            <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
              This checks the console service, not the signer topology, chain
              connections or recovery readiness.
            </p>
          </CardContent>
        </Card>
        <Alert className="border-warning/30 bg-warning/5">
          <LockKeyhole aria-hidden="true" />
          <AlertTitle>Production funding is blocked.</AlertTitle>
          <AlertDescription>
            Independent domains, separate approvals and a supported recovery
            drill still need evidence.
            <Link href="/readiness" className="mt-2 block underline">
              Inspect readiness requirements
            </Link>
          </AlertDescription>
        </Alert>
      </div>
    </div>
  );
}

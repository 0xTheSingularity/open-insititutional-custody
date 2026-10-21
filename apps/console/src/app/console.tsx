"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldCheck,
  LockKeyhole,
  LayoutGrid,
  List,
  RotateCw,
  CircleAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { SetupView } from "@/components/setup";
import { InventoryView } from "@/components/inventory";
import { ReadinessView } from "@/components/readiness";
import type { Snapshot, Preview } from "@/lib/contracts";

class RequestError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/console-api/v1/${path}`, {
      method,
      headers: { "Content-Type": "application/json", "X-OIC-Console": "1" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    throw new RequestError(
      "The service did not acknowledge this request. Reload saved state to check the outcome before trying again.",
    );
  }
  if (!response.ok) {
    const error = (await response.json().catch(() => null)) as {
      error?: string;
    } | null;
    throw new RequestError(
      error?.error ??
        `Request not completed (${response.status}). Check the input and reload saved state.`,
      response.status,
    );
  }
  return response.json() as Promise<T>;
}

const navigation = [
  {
    href: "/setup",
    label: "Getting started",
    mobileLabel: "Setup",
    icon: LayoutGrid,
  },
  {
    href: "/inventory",
    label: "Address inventory",
    mobileLabel: "Inventory",
    icon: List,
  },
  {
    href: "/readiness",
    label: "Readiness",
    mobileLabel: "Readiness",
    icon: ShieldCheck,
  },
];

export default function Console() {
  const pathname = usePathname();
  const current =
    navigation.find((item) => item.href === pathname) ?? navigation[0];
  const [data, setData] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [stale, setStale] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const inFlight = useRef(false);

  const perform = useCallback(
    async <T,>(action: () => Promise<T>): Promise<T | undefined> => {
      if (inFlight.current) return;
      inFlight.current = true;
      setBusy(true);
      setError("");
      setMessage("");
      try {
        return await action();
      } catch (error) {
        setError((error as Error).message);
        if (
          !(error instanceof RequestError) ||
          !error.status ||
          error.status === 409 ||
          error.status >= 500
        )
          setStale(true);
      } finally {
        inFlight.current = false;
        setBusy(false);
      }
    },
    [],
  );

  const reload = useCallback(async () => {
    await perform(async () => {
      setData(await api<Snapshot>("setup"));
      setStale(false);
    });
  }, [perform]);

  useEffect(() => {
    void reload();
    const focus = () => {
      void reload();
    };
    window.addEventListener("focus", focus);
    return () => window.removeEventListener("focus", focus);
  }, [reload]);

  const title =
    pathname === "/inventory"
      ? "Observe your existing treasury."
      : pathname === "/readiness"
        ? "Evidence before funding."
        : data?.setup.workspace_name
          ? "Pick up where you left off."
          : "Start with a safe first step.";

  return (
    <>
      <a
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-md focus:bg-card focus:p-3"
        href="#main"
      >
        Skip to content
      </a>
      <aside className="border-b bg-card px-4 pt-5 md:fixed md:inset-y-0 md:left-0 md:flex md:w-56 md:flex-col md:border-r md:border-b-0 md:px-4 md:py-7">
        <Link
          href="/setup"
          className="mb-6 flex items-center gap-3 px-2 text-sm font-semibold"
        >
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheck className="size-5" aria-hidden="true" />
          </span>
          <span>
            Open Institutional
            <span className="block font-normal text-muted-foreground">
              Custody
            </span>
          </span>
        </Link>
        <div className="mb-6 hidden rounded-lg border bg-muted/50 p-3 text-sm break-words md:block">
          {data?.setup.workspace_name ?? "Local workspace"}
          <span className="mt-1 block text-xs text-muted-foreground">
            Test environment
          </span>
        </div>
        <nav
          aria-label="Main navigation"
          className="grid grid-cols-3 gap-1 pb-3 md:flex md:flex-col"
        >
          {navigation.map((item) => (
            <Button
              key={item.href}
              asChild
              variant={pathname === item.href ? "secondary" : "ghost"}
              className="h-11 gap-2 px-3 text-xs md:justify-start md:text-sm"
            >
              <Link
                href={item.href}
                aria-current={pathname === item.href ? "page" : undefined}
              >
                <item.icon
                  className="hidden size-4 md:block"
                  aria-hidden="true"
                />
                <span className="hidden md:inline">{item.label}</span>
                <span className="md:hidden">{item.mobileLabel}</span>
              </Link>
            </Button>
          ))}
        </nav>
        <div className="mt-7 hidden md:block">
          <Separator />
          <div className="px-3 py-6 text-xs text-muted-foreground">
            <LockKeyhole className="mb-3 size-4" aria-hidden="true" />
            <strong className="text-foreground">No signing authority</strong>
            <p className="mt-2 leading-relaxed">
              This console can save public addresses. It cannot approve, sign or
              move funds.
            </p>
          </div>
        </div>
        <p className="mt-auto hidden px-3 text-xs text-muted-foreground md:block">
          A project by
          <br />
          <strong className="font-medium text-foreground">
            The Singularity
          </strong>
        </p>
      </aside>
      <div className="md:ml-56">
        <header className="flex min-h-16 items-center gap-4 border-b bg-card px-4 text-xs sm:px-8">
          <span className="mr-auto text-muted-foreground">
            Workspace <span className="px-2">/</span>
            {current.label}
          </span>
          <Badge variant="secondary">Test only</Badge>
          <span className="hidden text-muted-foreground sm:inline">
            Local source build
          </span>
        </header>
        <main
          id="main"
          tabIndex={-1}
          aria-busy={busy}
          className="mx-auto max-w-7xl space-y-6 p-4 pt-7 outline-none sm:p-8"
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-3xl font-semibold tracking-tight">{title}</h1>
              <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted-foreground">
                {pathname === "/inventory"
                  ? "Read-only inventory. Your current custodian keeps control."
                  : pathname === "/readiness"
                    ? "Setup progress is not production permission. Every missing control stays visible."
                    : "A local test workspace today. Independently verified custody before real funds."}
              </p>
            </div>
            <Button
              variant="outline"
              className="h-11"
              onClick={() => void reload()}
              disabled={busy}
            >
              <RotateCw aria-hidden="true" />
              Reload saved state
            </Button>
          </div>
          {error && (
            <Alert variant="destructive">
              <CircleAlert aria-hidden="true" />
              <AlertTitle>Request not completed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <Alert
            role="status"
            aria-live="polite"
            className={
              message
                ? "border-success/30 bg-success/5 text-success"
                : "sr-only"
            }
          >
            <AlertDescription className="text-inherit">
              {message || (busy ? "Request in progress." : "")}
            </AlertDescription>
          </Alert>
          {stale && data && (
            <Alert className="border-warning/30 bg-warning/5">
              <LockKeyhole aria-hidden="true" />
              <AlertTitle>Last-known state; actions are paused.</AlertTitle>
              <AlertDescription>
                Reload saved state to establish the latest outcome. Unsaved CSV
                content is not stored.
              </AlertDescription>
            </Alert>
          )}
          {!data && !error && (
            <Card role="status">
              <CardContent className="space-y-4">
                <span className="text-sm text-muted-foreground">
                  Connecting to the local console service…
                </span>
                <Skeleton className="h-6 w-2/3" />
                <Skeleton className="h-28 w-full" />
              </CardContent>
            </Card>
          )}
          {data && (
            <>
              {pathname === "/setup" && (
                <SetupView
                  snapshot={data}
                  disabled={busy || stale}
                  onCreate={(name) =>
                    perform(async () => {
                      const saved = await api<Snapshot>("workspace", "PUT", {
                        name,
                        base_revision: data.setup.revision,
                      });
                      setData(saved);
                      setMessage("Test workspace saved on this machine.");
                      return saved;
                    })
                  }
                />
              )}
              {pathname === "/inventory" && (
                <InventoryView
                  snapshot={data}
                  disabled={busy || stale}
                  onPreview={(csv) =>
                    perform(() =>
                      api<Preview>("inventory/preview", "POST", { csv }),
                    )
                  }
                  onSave={(csv) =>
                    perform(async () => {
                      const saved = await api<Snapshot>("inventory", "PUT", {
                        csv,
                        base_revision: data.setup.revision,
                      });
                      setData(saved);
                      setMessage(
                        "Watch-only addresses saved. No funds or signing authority moved.",
                      );
                      return saved;
                    })
                  }
                />
              )}
              {pathname === "/readiness" && <ReadinessView snapshot={data} />}
              <Separator />
              <footer className="flex flex-wrap justify-between gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-2">
                  <ShieldCheck className="size-4" aria-hidden="true" />
                  No private keys. No implicit approval authority.
                </span>
                <span>
                  {data.setup.updated_at
                    ? `Saved ${new Date(data.setup.updated_at * 1000).toLocaleString()} · revision ${data.setup.revision}`
                    : "No workspace saved yet"}
                </span>
              </footer>
            </>
          )}
        </main>
      </div>
    </>
  );
}

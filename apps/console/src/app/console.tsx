"use client";

import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldCheck,
  LockKeyhole,
  LayoutGrid,
  List,
  RotateCw,
  CircleAlert,
  ArrowLeftRight,
  PanelsTopLeft,
  Info,
  Wallet,
  ClipboardCheck,
  ContactRound,
  Workflow,
  History,
  Settings2,
  Menu,
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
import { ThemeToggle } from "@/components/theme-toggle";
import { TreasuryView, CustodyUnavailable } from "@/components/treasury";
import { TransferListView, TransferDetailView } from "@/components/transfers";
import {
  VaultsView,
  ApprovalsView,
  DestinationsView,
  OperationsView,
  ActivityView,
} from "@/components/workbench";
import { TransferComposer } from "@/components/transfer-composer";
import { AdministrationView } from "@/components/administration";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetTrigger,
} from "@/components/ui/sheet";
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
    href: "/overview",
    label: "Overview",
    icon: PanelsTopLeft,
  },
  { href: "/vaults", label: "Vaults", icon: Wallet },
  {
    href: "/transfers",
    label: "Transfers",
    icon: ArrowLeftRight,
  },
  { href: "/approvals", label: "Approvals", icon: ClipboardCheck },
  { href: "/destinations", label: "Destinations", icon: ContactRound },
  { href: "/operations", label: "Operations", icon: Workflow },
  { href: "/activity", label: "Activity", icon: History },
  { href: "/administration", label: "Administration", icon: Settings2 },
  {
    href: "/setup",
    label: "Getting started",
    icon: LayoutGrid,
  },
  {
    href: "/inventory",
    label: "Address inventory",
    icon: List,
  },
  {
    href: "/readiness",
    label: "Readiness",
    icon: ShieldCheck,
  },
];

export default function Console() {
  const pathname = usePathname();
  const current =
    navigation.find(
      (item) =>
        item.href === pathname ||
        pathname.startsWith(`${item.href}/`) ||
        (item.href === "/operations" && pathname.startsWith("/cases/")),
    ) ?? navigation[0];
  const [menuOpen, setMenuOpen] = useState(false);
  const [data, setData] = useState<Snapshot | null>(null);
  const demo = data?.mode === "demo";
  const treasury = data?.sample_treasury;
  const transfer = treasury?.transfers.find(
    (item) => pathname === `/transfers/${item.id}`,
  );
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
    pathname === "/overview"
      ? "Treasury overview"
      : pathname === "/transfers/new"
        ? "Explore transfer review"
        : pathname.startsWith("/transfers/")
          ? "Transfer details"
          : pathname.startsWith("/cases/")
            ? "Operational case"
            : pathname.startsWith("/vaults/")
              ? "Vault details"
              : pathname === "/readiness"
                ? "Production readiness"
                : pathname === "/setup"
                  ? "Workspace setup"
                  : current.label;

  const links = navigation.map((item, index) => (
    <Fragment key={item.href}>
      {(index === 0 || index === 7) && (
        <p className="console-nav-heading">
          {index === 0 ? "Operations" : "Workspace"}
        </p>
      )}
      <Button asChild variant="ghost" className="console-nav-link">
        <Link
          href={item.href}
          onClick={() => setMenuOpen(false)}
          aria-current={current.href === item.href ? "page" : undefined}
        >
          <item.icon className="size-4" aria-hidden="true" />
          {item.label}
        </Link>
      </Button>
    </Fragment>
  ));

  return (
    <>
      <a
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-md focus:bg-card focus:p-3"
        href="#main"
      >
        Skip to content
      </a>
      <aside className="console-rail">
        <Link
          href="/setup"
          className="console-brand"
          aria-label="The Singularity custody console"
        >
          <span className="console-mark" aria-hidden="true" />
          The Singularity
        </Link>
        <nav aria-label="Main navigation" className="space-y-1">
          {links}
        </nav>
        <div className="mt-auto hidden pt-16 lg:block">
          <Separator />
          <div className="space-y-4 px-3 py-5 text-xs text-muted-foreground">
            <div>
              <span>Test workspace</span>
              <p className="mt-1 break-words text-sm font-medium text-foreground">
                {data?.setup.workspace_name ?? "Local workspace"}
              </p>
            </div>
            <p className="flex items-center gap-2 text-foreground">
              <LockKeyhole className="size-3.5" aria-hidden="true" />
              No signing authority
            </p>
            <p className="leading-relaxed">
              {demo
                ? "Read-only examples. No saving, approvals or fund movement."
                : "Public-address metadata only. No approvals or fund movement."}
            </p>
          </div>
        </div>
      </aside>
      <div className="console-workspace">
        <header className="console-topbar text-xs">
          <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
            <SheetTrigger asChild>
              <Button
                variant="outline"
                size="icon"
                className="size-11 lg:hidden"
                aria-label="Open navigation"
              >
                <Menu aria-hidden="true" />
              </Button>
            </SheetTrigger>
            <SheetContent
              side="left"
              className="overflow-y-auto bg-card px-3 pb-6"
            >
              <SheetHeader>
                <SheetTitle>The Singularity</SheetTitle>
                <SheetDescription>
                  Test workspace · no signing authority
                </SheetDescription>
              </SheetHeader>
              <nav aria-label="Mobile navigation" className="space-y-1">
                {links}
              </nav>
            </SheetContent>
          </Sheet>
          <span className="mr-auto min-w-0 text-muted-foreground">
            Custody <span className="px-2">/</span>
            <span className="text-foreground">{current.label}</span>
          </span>
          <Badge
            variant="outline"
            className="hidden gap-2 px-3 py-1 sm:inline-flex"
          >
            <span
              className="size-1.5 rounded-full border border-current"
              aria-hidden="true"
            />
            {demo ? "Read-only sample" : "Local test"}
          </Badge>
          <ThemeToggle />
        </header>
        <main
          id="main"
          tabIndex={-1}
          aria-busy={busy}
          className="console-main space-y-8 outline-none"
        >
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="max-w-2xl">
              <h1 className="font-heading text-[32px] leading-tight font-normal tracking-[-0.02em] sm:text-4xl">
                {title}
              </h1>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                {[
                  "/overview",
                  "/vaults",
                  "/transfers",
                  "/approvals",
                  "/destinations",
                  "/operations",
                  "/activity",
                ].includes(current.href)
                  ? demo
                    ? "Historical treasury examples. Balances, approvals and chain outcomes are unverified."
                    : "Custody read models are not connected. Watch-only inventory does not establish balances or control."
                  : pathname === "/inventory"
                    ? demo
                      ? "Sample public identifiers. Balances and ownership are not verified."
                      : "Read-only inventory. Your current custodian keeps control."
                    : pathname === "/readiness"
                      ? "Setup progress is not production permission. Every missing control stays visible."
                      : demo
                        ? "Sample setup and administration requirements. No custody service is connected."
                        : "A local test workspace today. Independently verified custody before real funds."}
              </p>
            </div>
            <Button
              variant="outline"
              className="h-11 gap-2 sm:mt-1 sm:h-9"
              onClick={() => void reload()}
              disabled={busy}
            >
              <RotateCw aria-hidden="true" />
              {demo ? "Reload sample data" : "Reload saved state"}
            </Button>
          </div>
          {demo && (
            <Alert className="sample-notice">
              <Info aria-hidden="true" />
              <AlertTitle>Public sample. No real custody.</AlertTitle>
              <AlertDescription>
                No saving, approvals, signing or fund movement. CSV previews are
                temporary: use public test addresses only, never keys,
                credentials or private data.
              </AlertDescription>
            </Alert>
          )}
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
                ? "border-success-border bg-success-surface text-success"
                : "sr-only"
            }
          >
            <AlertDescription className="text-inherit">
              {message || (busy ? "Request in progress." : "")}
            </AlertDescription>
          </Alert>
          {stale && data && (
            <Alert className="border-warning-border bg-warning-surface">
              <LockKeyhole aria-hidden="true" />
              <AlertTitle>Last-known state; actions are paused.</AlertTitle>
              <AlertDescription>
                {demo ? "Reload sample data" : "Reload saved state"} to
                establish the latest outcome. Unsaved CSV content is not stored.
              </AlertDescription>
            </Alert>
          )}
          {!data && !error && (
            <Card role="status">
              <CardContent className="space-y-4">
                <span className="text-sm text-muted-foreground">
                  Connecting to the console service…
                </span>
                <Skeleton className="h-6 w-2/3" />
                <Skeleton className="h-28 w-full" />
              </CardContent>
            </Card>
          )}
          {data && (
            <>
              {pathname === "/overview" &&
                (treasury ? (
                  <TreasuryView treasury={treasury} />
                ) : (
                  <CustodyUnavailable />
                ))}
              {pathname === "/transfers" &&
                (treasury ? (
                  <TransferListView treasury={treasury} />
                ) : (
                  <CustodyUnavailable />
                ))}
              {transfer && treasury && (
                <TransferDetailView transfer={transfer} treasury={treasury} />
              )}
              {pathname === "/transfers/new" &&
                (treasury ? (
                  <TransferComposer treasury={treasury} />
                ) : (
                  <CustodyUnavailable />
                ))}
              {current.href === "/vaults" &&
                (treasury ? (
                  <VaultsView treasury={treasury} id={pathname.split("/")[2]} />
                ) : (
                  <CustodyUnavailable />
                ))}
              {pathname === "/approvals" &&
                (treasury ? (
                  <ApprovalsView treasury={treasury} />
                ) : (
                  <CustodyUnavailable />
                ))}
              {pathname === "/destinations" &&
                (treasury ? (
                  <DestinationsView treasury={treasury} />
                ) : (
                  <CustodyUnavailable />
                ))}
              {current.href === "/operations" &&
                (treasury ? (
                  <OperationsView
                    treasury={treasury}
                    caseId={
                      pathname.startsWith("/cases/")
                        ? pathname.split("/")[2]
                        : undefined
                    }
                  />
                ) : (
                  <CustodyUnavailable />
                ))}
              {pathname === "/activity" &&
                (treasury ? (
                  <ActivityView treasury={treasury} />
                ) : (
                  <CustodyUnavailable />
                ))}
              {current.href === "/administration" && (
                <AdministrationView
                  snapshot={data}
                  section={pathname.split("/")[2]}
                />
              )}
              {pathname === "/setup" && (
                <SetupView
                  snapshot={data}
                  disabled={busy || stale || demo}
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
                  {demo
                    ? "Read-only sample · no user data is saved"
                    : data.setup.updated_at
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

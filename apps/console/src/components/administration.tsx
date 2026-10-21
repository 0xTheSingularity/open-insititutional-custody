import Link from "next/link";
import { ArrowUpRight, LockKeyhole } from "lucide-react";
import { Button } from "@/components/ui/button";
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
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { Snapshot } from "@/lib/contracts";

const sections = [
  {
    id: "people",
    title: "People & access",
    description:
      "Separate login, business approval and administrative authority.",
  },
  {
    id: "policies",
    title: "Policies",
    description:
      "Inspect governance requirements before proposing a policy change.",
  },
  {
    id: "signers",
    title: "Signers & authority",
    description:
      "Domain ownership, generations, approved builds and local controls.",
  },
  {
    id: "recovery",
    title: "Recovery",
    description:
      "Supported recovery profiles, drill evidence and exit readiness.",
  },
  {
    id: "integrations",
    title: "Integrations",
    description:
      "Scoped API access, event subscriptions and delivery evidence.",
  },
  {
    id: "migration",
    title: "Migration",
    description:
      "Watch-only discovery through independently reconciled migration.",
  },
];

export function AdministrationView({
  snapshot,
  section,
}: {
  snapshot: Snapshot;
  section?: string;
}) {
  const current = sections.find((item) => item.id === section);
  const rows =
    section === "people"
      ? [
          [
            "Console sessions",
            "Institution identity and session revocation",
            "No institution session connected",
          ],
          [
            "Proposer / API credentials",
            "Scoped credential inventory, expiry and revocation",
            "No credential inventory connected",
          ],
          [
            "Business approval grants",
            "Independent credentials and outstanding grant scope",
            "No grant inventory connected",
          ],
          [
            "Administrative credentials",
            "Independent administrative quorum and replacement",
            "No administrative authority connected",
          ],
          [
            "Automation delegations",
            "Workflow scopes, bounded authority and revocation",
            "No delegation inventory connected",
          ],
          [
            "MPC / recovery authority",
            "Supported replacement or rotation procedure",
            "Requires domain-local verification",
          ],
        ]
      : section === "policies"
        ? [
            [
              "Active policy",
              "Signed version, epoch and affected vaults",
              "Not supplied",
            ],
            [
              "Proposed change",
              "Before/after scope, base version, owner and expiry",
              "No governed proposal connected",
            ],
            [
              "Evaluation",
              "Hard-deny dominance and fail-closed constraints",
              "No policy simulation connected",
            ],
            [
              "Activation",
              "Distinct administrators, delay and verified receipt",
              "Not available",
            ],
          ]
        : section === "signers"
          ? [
              [
                "Domain roster",
                "Owner, membership version and generation",
                "Not connected",
              ],
              [
                "Approved software",
                "Build provenance, measurements and capability profile",
                "Not verified",
              ],
              [
                "Authority continuity",
                "Ordered issuance, fencing and checkpoint lineage",
                "Not verified",
              ],
              [
                "Local halt / resume",
                "Domain-local operator procedure",
                "Not available from this console",
              ],
            ]
          : section === "recovery"
            ? [
                [
                  "Permitted signer loss",
                  "Supported replacement profile and domain owners",
                  "No profile verified",
                ],
                [
                  "Authority restore",
                  "Fenced restore, issuance continuity and checkpoint comparison",
                  "No restore evidence supplied",
                ],
                [
                  "Approver device loss",
                  "Independent credential replacement and revocation",
                  "No replacement authority connected",
                ],
                [
                  "Recovery drill",
                  "Dated results, prerequisites and permitted-loss test",
                  "No drill evidence supplied",
                ],
                [
                  "Exit readiness",
                  "Documented history, public verification and recovery runbook",
                  "Not certified",
                ],
              ]
            : section === "integrations"
              ? [
                  [
                    "API credentials",
                    "Vault scope, read/propose/approve/submit capability and expiry",
                    "No credentials provisioned here",
                  ],
                  [
                    "Event subscriptions",
                    "Event kinds, signing-key version and delivery attempts",
                    "No subscription service connected",
                  ],
                  [
                    "Sequence continuity",
                    "Last acknowledgement, gaps and permitted replay range",
                    "No signed sequence connected",
                  ],
                  [
                    "Secret delivery",
                    "Approved private delivery mechanism, outside ordinary exports",
                    "Not available",
                  ],
                ]
              : [
                  [
                    "Watch-only discovery",
                    "Public address inventory; no control transferred",
                    `${snapshot.setup.inventory.length} metadata records`,
                  ],
                  [
                    "Semantic-gap review",
                    "Address compatibility, asset support and retained authority",
                    "Not verified",
                  ],
                  [
                    "Readiness",
                    "Recovery, policy, custody and evidence prerequisites",
                    "Production blocked",
                  ],
                  [
                    "Canary",
                    "Normal authorized transfer and independent reconciliation",
                    "Not run",
                  ],
                  [
                    "Batch / source exit",
                    "Approved manifest, per-item outcomes and residual authority",
                    "Not available",
                  ],
                ];
  return (
    <div className="space-y-6">
      <Alert>
        <LockKeyhole aria-hidden="true" />
        <AlertTitle>
          Administration preview. No privileges are granted.
        </AlertTitle>
        <AlertDescription>
          These public screens explain the required controls. Institution
          authentication, scoped administrative reads and independent
          administrative verification are not connected. No users, policies,
          signers or credentials can be changed.
        </AlertDescription>
      </Alert>
      {!current ? (
        <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
          {sections.map((item) => (
            <Card key={item.id}>
              <CardHeader>
                <CardTitle>
                  <h2>{item.title}</h2>
                </CardTitle>
                <CardDescription>{item.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <Button asChild variant="outline">
                  <Link href={`/administration/${item.id}`}>
                    Inspect requirements
                    <ArrowUpRight aria-hidden="true" />
                  </Link>
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <>
          <nav
            aria-label="Administration sections"
            className="flex flex-wrap gap-2"
          >
            {sections.map((item) => (
              <Button
                key={item.id}
                asChild
                variant={item.id === section ? "secondary" : "outline"}
                className="h-11"
              >
                <Link
                  href={`/administration/${item.id}`}
                  aria-current={item.id === section ? "page" : undefined}
                >
                  {item.title}
                </Link>
              </Button>
            ))}
          </nav>
          <Card>
            <CardHeader>
              <CardTitle className="flex flex-wrap items-start justify-between gap-3">
                <h2>{current.title}</h2>
                <Badge variant="outline">
                  {section === "migration"
                    ? "Watch-only metadata"
                    : "Not connected"}
                </Badge>
              </CardTitle>
              <CardDescription>{current.description}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <p className="text-xs text-muted-foreground">
                Scroll the table horizontally for all evidence and states.
                Keyboard: focus the table, then use the arrow keys.
              </p>
              <Table
                aria-label={`${current.title} requirements and current state`}
              >
                <TableHeader>
                  <TableRow>
                    <TableHead>Scope</TableHead>
                    <TableHead>Required evidence</TableHead>
                    <TableHead>Current state</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map(([scope, evidence, state]) => (
                    <TableRow key={scope}>
                      <TableCell className="min-w-40 whitespace-normal font-medium">
                        {scope}
                      </TableCell>
                      <TableCell className="min-w-60 whitespace-normal leading-relaxed text-muted-foreground">
                        {evidence}
                      </TableCell>
                      <TableCell className="min-w-44 whitespace-normal">
                        {state}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <div className="max-w-3xl space-y-3 border-t pt-5 text-sm leading-relaxed">
                <h3 className="font-medium">
                  {section === "people"
                    ? "Offboarding is not a single switch"
                    : section === "policies"
                      ? "A draft never changes the active policy"
                      : section === "signers"
                        ? "Local halt is separate from a global freeze"
                        : section === "recovery"
                          ? "A backup is not a completed recovery drill"
                          : section === "integrations"
                            ? "API access does not bypass signed approval"
                            : "Discovery does not migrate custody"}
                </h3>
                <p className="text-muted-foreground">
                  {section === "people"
                    ? "Each authority must be reviewed independently. A login reset restores no signing authority, logout cannot revoke issued signatures, and removal of MPC or recovery access can require manual rotation. This page makes no All access removed claim."
                    : section === "policies"
                      ? "Hard denials dominate; reordering rules cannot bypass them. A governed change needs a current base version, explicit privilege expansion, distinct administrative approval, any activation delay and a verified activation receipt. Historical simulation alone does not establish safety."
                      : section === "signers"
                        ? "Domain controls and ceremonies belong to their protected local surface. An emergency freeze blocks future release only after its ordered commit point; it cannot cancel a signature already issued. This app cannot collect shares, reset preprocessing or rewind issuance."
                        : section === "recovery"
                          ? "Classify the loss before starting. Recovery requires the declared supported profile, fenced processes and verified generation/checkpoint continuity. Loss beyond that profile stays blocked. This browser never reconstructs a full private key or downloads secret material."
                          : section === "integrations"
                            ? "Read, propose, approve and submit are distinct capabilities. Credentials never replace independent signed grants. Event replay redelivers events, not payments; consumers must deduplicate and repair gaps. Do not paste API secrets into this public sample."
                            : "Importing addresses records public metadata only. It does not retain an old custodian's addresses, enroll signing authority, complete a canary or decommission the source. A partially completed migration must keep residual authority and unresolved items visible."}
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                <Button disabled aria-describedby="admin-reason">
                  {section === "people"
                    ? "Invite or change authority"
                    : section === "policies"
                      ? "Propose policy change"
                      : section === "signers"
                        ? "Open protected domain control"
                        : section === "recovery"
                          ? "Start supported recovery"
                          : section === "integrations"
                            ? "Provision scoped integration"
                            : "Start migration canary"}
                </Button>
                <Button asChild variant="outline">
                  <Link
                    href={section === "migration" ? "/inventory" : "/readiness"}
                  >
                    {section === "migration"
                      ? "Inspect address inventory"
                      : "Inspect readiness blockers"}
                  </Link>
                </Button>
              </div>
              <p id="admin-reason" className="text-xs text-muted-foreground">
                Unavailable without authenticated scope, the applicable backend
                capability and independent authorization. No privileged request
                is sent.
              </p>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

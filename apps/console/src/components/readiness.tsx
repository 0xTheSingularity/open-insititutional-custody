import { Download, LockKeyhole } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import type { Snapshot } from "@/lib/contracts";

export function ReadinessView({ snapshot }: { snapshot: Snapshot }) {
  return (
    <div className="space-y-6">
      <Alert className="border-warning-border bg-warning-surface">
        <LockKeyhole aria-hidden="true" />
        <AlertTitle>Not ready for production funds.</AlertTitle>
        <AlertDescription>
          This local source-build console has no authenticated institution
          sessions or live custody connection. A completed inventory is not a
          control-plane deployment.
        </AlertDescription>
      </Alert>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between gap-4">
            <h2>Required evidence</h2>
            <Badge variant="outline" className="text-warning">
              {snapshot.blockers.length} blockers
            </Badge>
          </CardTitle>
          <CardDescription>
            There is no “mark ready” override. Responsible services and domain
            owners must supply verifiable evidence.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="divide-y">
            {snapshot.blockers.map((blocker) => (
              <li
                key={blocker.title}
                className="flex flex-wrap items-start gap-3 py-5"
              >
                <LockKeyhole
                  className="mt-1 size-4 text-muted-foreground"
                  aria-hidden="true"
                />
                <div className="min-w-48 flex-1">
                  <h3 className="font-medium">{blocker.title}</h3>
                  <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">
                    {blocker.reason}
                  </p>
                </div>
                <Badge variant="outline" className="text-warning">
                  Not verified
                </Badge>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Keep a portable inventory.</h2>
          </CardTitle>
          <CardDescription>
            Export public addresses, source provenance, setup revision and
            remaining blockers. This unsigned report is not a reconciliation
            checkpoint or a verified custody audit.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline" className="h-11">
            <a href="/console-api/v1/export" download>
              <Download aria-hidden="true" />
              Export readiness & inventory
            </a>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

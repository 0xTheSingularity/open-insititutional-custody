import { notFound } from "next/navigation";
import Console from "../../console";
import { sampleTreasury } from "@/lib/sample-treasury";

export default async function OperatorPage({
  params,
}: {
  params: Promise<{ section: string; detail?: string[] }>;
}) {
  const { section, detail = [] } = await params;
  const [id] = detail;
  const sample = process.env.OIC_CONSOLE_DEMO === "1";
  const valid =
    detail.length <= 1 &&
    ((section === "vaults" &&
      (!id ||
        (sample && sampleTreasury.holdings.some((item) => item.id === id)))) ||
      (["approvals", "destinations", "operations", "activity"].includes(
        section,
      ) &&
        !id) ||
      (section === "cases" &&
        sample &&
        sampleTreasury.transfers.some(
          (item) =>
            item.id === id &&
            (item.state === "SubmissionUnknown" ||
              (item.state === "FinalizedSuccess" &&
                item.reconciliation === "pending")),
        )) ||
      (section === "administration" &&
        (!id ||
          [
            "people",
            "policies",
            "signers",
            "recovery",
            "integrations",
            "migration",
          ].includes(id))));
  if (!valid) notFound();
  return <Console />;
}

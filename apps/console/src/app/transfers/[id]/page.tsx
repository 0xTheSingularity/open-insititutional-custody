import { notFound } from "next/navigation";
import Console from "../../console";
import { sampleTreasury } from "@/lib/sample-treasury";

export default async function TransferPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  if (
    process.env.OIC_CONSOLE_DEMO === "1"
      ? !sampleTreasury.transfers.some((transfer) => transfer.id === id)
      : !/^[A-Za-z0-9_-]{1,128}$/.test(id)
  )
    notFound();
  return <Console />;
}

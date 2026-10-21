import { handleCustody } from "@/lib/custody-server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const GET = (request: Request) => handleCustody(request);
export const POST = (request: Request) => handleCustody(request);

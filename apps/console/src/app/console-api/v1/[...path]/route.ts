import { handle } from "../../../../lib/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const GET = (request: Request) => handle(request);
export const POST = (request: Request) => handle(request);
export const PUT = (request: Request) => handle(request);

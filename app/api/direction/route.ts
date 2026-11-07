import { NextResponse } from "next/server";
import { directionMetrics } from "@/lib/direction";
import { requireTenant } from "@/lib/tenant";

export const dynamic = "force-dynamic";

export async function GET() {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  try {
    return NextResponse.json({ org: t.orgName, ...(await directionMetrics(t.orgId)) }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (e) {
    console.error(`[direction] ${e instanceof Error ? e.message : e}`);
    return NextResponse.json({ error: "Indicateurs momentanément indisponibles." }, { status: 500 });
  }
}

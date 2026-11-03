import { NextResponse } from "next/server";
import { requireTenant } from "@/lib/tenant";
import { listUserLeaks } from "@/lib/cti/leakstore";

export const dynamic = "force-dynamic";

/** Fuites du darkweb rapprochées de la liste de surveillance de l'utilisateur. */
export async function GET() {
  const s = await requireTenant("viewer");
  if (s instanceof NextResponse) return s;
  return NextResponse.json({ leaks: await listUserLeaks(s.orgId) }, { headers: { "Cache-Control": "private, no-store" } });
}

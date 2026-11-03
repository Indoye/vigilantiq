import { NextResponse } from "next/server";
import { requireTenant } from "@/lib/tenant";
import { markSeen } from "@/lib/cti/store";

export const dynamic = "force-dynamic";

/** Marque des alertes comme lues : { ids: [1, 2] } ou { ids: "all" }. */
export async function PATCH(req: Request) {
  const s = await requireTenant("viewer");
  if (s instanceof NextResponse) return s;
  const body = (await req.json().catch(() => null)) as { ids?: unknown } | null;
  const ids = body?.ids === "all" ? "all" : Array.isArray(body?.ids) ? body!.ids.filter((x): x is number => Number.isInteger(x)).slice(0, 500) : null;
  if (!ids) return NextResponse.json({ error: "Liste d’alertes invalide." }, { status: 400 });
  await markSeen(s.orgId, ids);
  return NextResponse.json({ ok: true });
}

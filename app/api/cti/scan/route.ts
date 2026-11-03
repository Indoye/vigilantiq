import { NextResponse } from "next/server";
import { requireTenant } from "@/lib/tenant";
import { listWatch, scanUser } from "@/lib/cti/store";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

const MIN_INTERVAL_MS = 5 * 60 * 1000;

/** Lance l'analyse de la liste de surveillance de l'utilisateur (au plus une fois toutes les 5 minutes). */
export async function POST() {
  const s = await requireTenant("analyst");
  if (s instanceof NextResponse) return s;
  const items = await listWatch(s.orgId);
  const last = Math.max(0, ...items.map((i) => (i.lastScanAt ? Date.parse(i.lastScanAt) : 0)));
  if (Date.now() - last < MIN_INTERVAL_MS) {
    const wait = Math.ceil((MIN_INTERVAL_MS - (Date.now() - last)) / 60000);
    return NextResponse.json({ error: `Analyse déjà lancée récemment : réessayez dans ${wait} min.` }, { status: 429 });
  }
  const result = await scanUser(s.orgId, s.user.emailVerified ? s.email : null);
  return NextResponse.json(result);
}

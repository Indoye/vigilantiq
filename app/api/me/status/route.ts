import { NextResponse } from "next/server";
import { requireTenant } from "@/lib/tenant";
import { CVE_ID_RE } from "@/lib/detail";
import { setStatus, STATUSES, type CveStatusValue } from "@/lib/userdata";

export const dynamic = "force-dynamic";

/** Change le suivi d'une CVE : à traiter, en cours, traitée, non concernée. */
export async function PUT(req: Request) {
  const s = await requireTenant("analyst");
  if (s instanceof NextResponse) return s;
  const body = (await req.json().catch(() => null)) as { cveId?: unknown; status?: unknown } | null;
  const cveId = typeof body?.cveId === "string" ? body.cveId.toUpperCase() : "";
  if (!CVE_ID_RE.test(cveId) || !(STATUSES as readonly unknown[]).includes(body?.status)) {
    return NextResponse.json({ error: "Identifiant CVE ou statut invalide." }, { status: 400 });
  }
  await setStatus(s.orgId, cveId, body!.status as CveStatusValue);
  return NextResponse.json({ cveId, status: body!.status });
}

/** Actions groupées : { cveIds: string[], status } */
export async function PATCH(req: Request) {
  const s = await requireTenant("analyst");
  if (s instanceof NextResponse) return s;
  const body = (await req.json().catch(() => null)) as { cveIds?: unknown; status?: unknown } | null;
  const ids = Array.isArray(body?.cveIds) ? body.cveIds.filter((x): x is string => typeof x === "string").map((x) => x.toUpperCase()).filter((x) => CVE_ID_RE.test(x)).slice(0, 200) : [];
  if (!ids.length || !(STATUSES as readonly unknown[]).includes(body?.status)) {
    return NextResponse.json({ error: "Sélection ou statut invalide." }, { status: 400 });
  }
  for (const id of ids) await setStatus(s.orgId, id, body!.status as CveStatusValue);
  return NextResponse.json({ ok: true, count: ids.length, status: body!.status });
}

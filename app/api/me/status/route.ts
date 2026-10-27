import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { CVE_ID_RE } from "@/lib/detail";
import { setStatus, STATUSES, type CveStatusValue } from "@/lib/userdata";

export const dynamic = "force-dynamic";

/** Change le suivi d'une CVE : à traiter, en cours, traitée, non concernée. */
export async function PUT(req: Request) {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Session expirée. Reconnectez-vous." }, { status: 401 });
  const body = (await req.json().catch(() => null)) as { cveId?: unknown; status?: unknown } | null;
  const cveId = typeof body?.cveId === "string" ? body.cveId.toUpperCase() : "";
  if (!CVE_ID_RE.test(cveId) || !(STATUSES as readonly unknown[]).includes(body?.status)) {
    return NextResponse.json({ error: "Identifiant CVE ou statut invalide." }, { status: 400 });
  }
  await setStatus(s.user.id, cveId, body!.status as CveStatusValue);
  return NextResponse.json({ cveId, status: body!.status });
}

import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { CVE_ID_RE, getCveDetail } from "@/lib/detail";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Fiche complète d'une CVE (versions impactées, références, mentions dans les flux). */
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  // Contrôle complet de la session : cette route peut déclencher un résumé IA.
  if (!(await currentSession())) return NextResponse.json({ error: "Session expirée. Reconnectez-vous." }, { status: 401 });
  const { id } = await ctx.params;
  const cve = id.toUpperCase();
  if (!CVE_ID_RE.test(cve)) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  const detail = await getCveDetail(cve);
  if (!detail) return NextResponse.json({ error: `${cve} introuvable dans NVD et CVE.org` }, { status: 404 });
  return NextResponse.json(detail);
}

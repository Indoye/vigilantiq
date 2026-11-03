import { NextResponse } from "next/server";
import { currentTenant } from "@/lib/tenant";
import { CVE_ID_RE, getCveDetail } from "@/lib/detail";
import { getGuestCve } from "@/lib/publiccve";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Fiche complète d'une CVE (versions impactées, références, mentions dans les flux). */
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  // Contrôle complet de la session : seuls les utilisateurs connectés déclenchent un résumé IA.
  // Sans compte : fiche publique, sans IA ni tickets, en cache.
  const tenant = await currentTenant();
  const { id } = await ctx.params;
  const cve = id.toUpperCase();
  if (!CVE_ID_RE.test(cve)) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  // Tickets : ceux de l'organisation de l'utilisateur uniquement.
  const detail = tenant ? await getCveDetail(cve, { orgId: tenant.orgId }) : await getGuestCve(cve);
  if (!detail) return NextResponse.json({ error: `${cve} introuvable dans NVD et CVE.org` }, { status: 404 });
  return NextResponse.json(detail);
}

import { NextResponse } from "next/server";
import { authorize, unauthorized } from "@/lib/apiauth";
import { CVE_ID_RE, getCveDetail } from "@/lib/detail";
import { renderPdf } from "@/lib/pdfrender";
import { cveReport } from "@/lib/reportmodel";
import { generatedLabel, pdfResponse, stamp } from "@/lib/reportroute";
import { appUrl } from "@/lib/ticketstore";
import { getStatuses } from "@/lib/userdata";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Rapport PDF exhaustif d'une CVE. ?inline=1 pour l'ouvrir dans le navigateur plutôt que le télécharger. */
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const caller = await authorize(req);
  if (!caller) return unauthorized();
  const id = (await ctx.params).id.toUpperCase();
  if (!CVE_ID_RE.test(id)) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  const detail = await getCveDetail(id);
  if (!detail) return NextResponse.json({ error: `${id} introuvable dans NVD et CVE.org` }, { status: 404 });

  const status = caller.kind === "session" ? ((await getStatuses(caller.userId).catch(() => ({}) as Record<string, string>))[id] ?? "a_traiter") : undefined;
  const context = { generatedAt: new Date(), generatedBy: caller.kind === "session" ? caller.email : `API (${caller.name})`, appUrl: appUrl(), status };
  const { meta, blocks } = cveReport(detail, context);
  const pdf = await renderPdf(meta, blocks, generatedLabel(context));
  return pdfResponse(pdf, `VigilantIQ-${id}-${stamp(context.generatedAt)}.pdf`, new URL(req.url).searchParams.get("inline") === "1");
}

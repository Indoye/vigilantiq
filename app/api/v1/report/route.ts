import { NextResponse } from "next/server";
import { authorize, unauthorized } from "@/lib/apiauth";
import { filterVulns, parseVulnQuery } from "@/lib/apifilter";
import { getCachedFeed } from "@/lib/feedcache";
import { renderPdf } from "@/lib/pdfrender";
import { selectionReport } from "@/lib/reportmodel";
import { generatedLabel, pdfResponse, stamp } from "@/lib/reportroute";
import { appUrl } from "@/lib/ticketstore";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 120;

const MAX = 50;

/**
 * Rapport PDF d'une sélection de vulnérabilités du jour : vue d'ensemble, puis une fiche complète par CVE.
 * Sélection par ids=CVE-…,CVE-… (ordre conservé) ou par les filtres de /api/v1/vulns. titre= pour le titre.
 */
export async function GET(req: Request) {
  const caller = await authorize(req);
  if (!caller) return unauthorized();
  const sp = new URL(req.url).searchParams;
  const feed = await getCachedFeed();

  let vulns;
  let scope: string;
  const ids = (sp.get("ids") ?? "")
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
  if (ids.length) {
    const byId = new Map(feed.vulns.map((v) => [v.id, v]));
    vulns = ids.map((id) => byId.get(id)).filter((v) => v !== undefined);
    scope = "sélection";
  } else {
    const q = parseVulnQuery(sp);
    if ("error" in q) return NextResponse.json({ error: q.error }, { status: 400 });
    vulns = filterVulns(feed.vulns, q);
    scope = `flux des ${feed.windowHours} dernières heures`;
  }
  if (vulns.length > MAX) {
    return NextResponse.json({ error: `Trop de vulnérabilités (${vulns.length}) : ${MAX} au maximum par rapport. Affinez les filtres.` }, { status: 413 });
  }

  const title = (sp.get("titre") ?? sp.get("title") ?? "Rapport de veille").slice(0, 80);
  const context = { generatedAt: new Date(), generatedBy: caller.kind === "session" ? caller.email : `API (${caller.name})`, appUrl: appUrl(), title, scope };
  const { meta, blocks } = selectionReport(vulns, context);
  const pdf = await renderPdf(meta, blocks, generatedLabel(context));
  const slug = title.normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "") || "rapport";
  return pdfResponse(pdf, `VigilantIQ-${slug}-${stamp(context.generatedAt)}.pdf`, sp.get("inline") === "1");
}

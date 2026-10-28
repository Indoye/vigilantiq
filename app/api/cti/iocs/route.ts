import { NextResponse } from "next/server";
import { iocsToCsv, iocsToStix } from "@/lib/cti/export";
import type { Ioc } from "@/lib/cti/sources";
import { getIocs } from "@/lib/cti/store";
import { countBy } from "@/lib/cti/stats";

export const dynamic = "force-dynamic";

const TYPES = new Set(["ip", "ip:port", "domain", "url", "md5", "sha1", "sha256", "hash"]);

/**
 * Indicateurs de compromission (abuse.ch, OpenPhish), filtrables et exportables.
 * ?type=url|ip|domain|hash  ?q=texte  ?source=…  ?format=json|csv|stix  ?limit=…
 */
export async function GET(req: Request) {
  const sp = new URL(req.url).searchParams;
  let feed;
  try {
    feed = await getIocs();
  } catch (e) {
    return NextResponse.json({ error: `Flux d’IOC indisponibles : ${e instanceof Error ? e.message : e}` }, { status: 502 });
  }
  const type = sp.get("type") ?? "";
  const q = (sp.get("q") ?? "").trim().toLowerCase();
  const source = sp.get("source") ?? "";
  const limit = Math.min(5000, Math.max(1, Number(sp.get("limit")) || 500));
  const items = feed.items.filter((i: Ioc) => {
    if (TYPES.has(type)) {
      if (type === "hash" ? !["md5", "sha1", "sha256"].includes(i.type) : type === "ip" ? !i.type.startsWith("ip") : i.type !== type) return false;
    }
    if (source && i.source !== source) return false;
    if (q && !`${i.value} ${i.malware} ${i.threat} ${i.tags.join(" ")}`.toLowerCase().includes(q)) return false;
    return true;
  });
  const out = items.slice(0, limit);
  const format = sp.get("format");
  const stamp = new Date().toISOString().slice(0, 10);
  if (format === "csv") {
    return new NextResponse(iocsToCsv(out), {
      headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="vigilantiq-ioc-${stamp}.csv"` },
    });
  }
  if (format === "stix") {
    return new NextResponse(JSON.stringify(iocsToStix(out), null, 1), {
      headers: { "Content-Type": "application/stix+json; charset=utf-8", "Content-Disposition": `attachment; filename="vigilantiq-ioc-${stamp}.stix.json"` },
    });
  }
  return NextResponse.json(
    {
      generatedAt: feed.generatedAt,
      total: items.length,
      sources: feed.sources,
      types: countBy(feed.items, (i) => (i.type.startsWith("ip") ? "ip" : ["md5", "sha1", "sha256"].includes(i.type) ? "hash" : i.type)),
      malware: countBy(feed.items, (i) => i.malware, 10),
      items: out,
    },
    { headers: { "Cache-Control": "public, max-age=300" } },
  );
}

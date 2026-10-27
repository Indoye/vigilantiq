import { NextResponse } from "next/server";
import { authorize, unauthorized } from "@/lib/apiauth";
import { filterVulns, parseVulnQuery } from "@/lib/apifilter";
import { getCachedFeed } from "@/lib/feedcache";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** Vulnérabilités du jour, filtrables, pour SIEM, SOAR, ITSM et scripts. */
export async function GET(req: Request) {
  if (!(await authorize(req))) return unauthorized();
  const query = parseVulnQuery(new URL(req.url).searchParams);
  if ("error" in query) return NextResponse.json({ error: query.error }, { status: 400 });
  const feed = await getCachedFeed();
  const items = filterVulns(feed.vulns, query);
  return NextResponse.json({ generatedAt: feed.generatedAt, windowHours: feed.windowHours, count: items.length, items });
}

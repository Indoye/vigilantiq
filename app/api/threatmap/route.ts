import { unstable_cache } from "next/cache";
import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { buildThreatMap, PERIODS, type Period } from "@/lib/threatmap";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

/** Données de la ThreatMap (flux Cloudflare Radar, C2 abuse.ch, ports DShield), en cache 5 minutes. */
export async function GET(req: Request) {
  if (!(await currentSession())) return NextResponse.json({ error: "Session expirée. Reconnectez-vous." }, { status: 401 });
  const q = new URL(req.url).searchParams;
  const period = (PERIODS as string[]).includes(q.get("periode") ?? "") ? (q.get("periode") as Period) : "1d";
  const pays = (q.get("pays") ?? "").toUpperCase();
  const country = /^[A-Z]{2}$/.test(pays) ? pays : null;
  const data = await unstable_cache(() => buildThreatMap(period, country), ["threatmap-v1", period, country ?? "-"], {
    revalidate: 300,
    tags: ["threatmap"],
  })();
  return NextResponse.json(data, { headers: { "Cache-Control": "private, max-age=60" } });
}

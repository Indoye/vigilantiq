import { unstable_cache } from "next/cache";
import { NextResponse } from "next/server";
import { buildFocus } from "@/lib/threatfocusbuild";
import { PERIODS, type Period } from "@/lib/threatmap";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

/** Écosystème des attaques d'un pays (Sénégal par défaut, ou THREATMAP_FOCUS) — données publiques, en cache 15 minutes. */
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams;
  const period = (PERIODS as string[]).includes(q.get("periode") ?? "") ? (q.get("periode") as Period) : "7d";
  const raw = (q.get("pays") ?? process.env.THREATMAP_FOCUS ?? "SN").toUpperCase();
  const cc = /^[A-Z]{2}$/.test(raw) ? raw : "SN";
  const data = await unstable_cache(() => buildFocus(cc, period), ["threatfocus-v1", cc, period], { revalidate: 900, tags: ["threatmap"] })();
  return NextResponse.json(data, { headers: { "Cache-Control": "private, max-age=120" } });
}

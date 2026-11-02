import { NextResponse } from "next/server";
import { patchDaily } from "@/lib/patch/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/**
 * Passe quotidienne du module Parc & correctifs (Vercel Cron, protégée par CRON_SECRET) : nouvelle corrélation des
 * équipements avec les CVE publiées depuis la veille, politiques automatiques, avancement des déploiements, purge.
 */
export async function GET(req: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers.get("authorization") !== `Bearer ${secret}`) return NextResponse.json({ error: "Non autorisé" }, { status: 401 });
  try {
    return NextResponse.json(await patchDaily());
  } catch (e) {
    console.error(`[parc] passe quotidienne : ${e instanceof Error ? e.message : e}`);
    return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 });
  }
}

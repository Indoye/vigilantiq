import { after, NextResponse } from "next/server";
import { dbConfigured } from "@/db";
import { feedVersion, isStale, refreshFeed } from "@/lib/feedstore";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/**
 * Version du flux de vulnérabilités (légère) : les navigateurs l'interrogent toutes les 3 min pour proposer
 * la mise à jour, et l'ordonnanceur externe toutes les 10 min.
 * Si l'instantané a plus de FEED_REFRESH_MINUTES, une collecte est lancée après la réponse
 * (une seule à la fois, au plus une toutes les 4 min : l'appel peut être public sans risque d'abus).
 */
export async function GET() {
  if (!dbConfigured()) return NextResponse.json({ error: "Base de données non configurée" }, { status: 503 });
  try {
    const v = await feedVersion();
    const stale = isStale(v);
    if (stale && !v.refreshing) after(() => refreshFeed().then(() => undefined));
    return NextResponse.json({ ...v, stale }, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "Erreur" }, { status: 500 });
  }
}

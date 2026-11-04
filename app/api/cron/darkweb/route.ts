import { NextResponse } from "next/server";
import { darkwebDaily } from "@/lib/darkweb/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/**
 * Collecte du dark web (Vercel Cron, deux passes par jour) : ingestion des runs Apify terminés
 * (masquage, indexation, percolation des motifs, alertes), puis lancement des sources à rafraîchir.
 */
export async function GET(req: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers.get("authorization") !== `Bearer ${secret}`) {
    return NextResponse.json({ error: "Non autorisé" }, { status: 401 });
  }
  try {
    return NextResponse.json(await darkwebDaily(240_000));
  } catch (e) {
    console.error(`[dark web] passe planifiée : ${e instanceof Error ? e.message : e}`);
    return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 });
  }
}

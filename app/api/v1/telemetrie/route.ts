import { NextResponse } from "next/server";
import { LIMITS } from "@/lib/hunt/core";
import { authenticateAgent, HuntError, ingestAgent } from "@/lib/hunt/store";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/**
 * Réception des données de l'agent collecteur (texte, une ligne par élément).
 * En-têtes : Authorization: Bearer <clé de l'équipement>, X-VQ-Timestamp, X-VQ-Signature: sha256=<HMAC(clé, « horodatage.corps »)>.
 */
export async function POST(req: Request) {
  if (Number(req.headers.get("content-length") || 0) > LIMITS.bodyBytes) return NextResponse.json({ error: "Corps trop volumineux." }, { status: 413 });
  const raw = await req.text();
  if (raw.length > LIMITS.bodyBytes) return NextResponse.json({ error: "Corps trop volumineux." }, { status: 413 });
  try {
    const asset = await authenticateAgent(req.headers, raw);
    return NextResponse.json(await ingestAgent(asset, raw), { status: 202 });
  } catch (e) {
    if (e instanceof HuntError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error(`[chasse] agent : ${e instanceof Error ? e.message : e}`);
    return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
  }
}

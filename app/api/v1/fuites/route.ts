import { after, NextResponse } from "next/server";
import { LIMITS } from "@/lib/cti/leaks";
import { authenticateIngest, enqueue, LeakError, processQueue } from "@/lib/cti/leakstore";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/**
 * Ingestion d'événements de fuite (collecteurs, fournisseurs, partenaires).
 *
 * En-têtes : Authorization: Bearer <clé de la source>, X-VQ-Timestamp (secondes Unix),
 * X-VQ-Signature: sha256=<HMAC-SHA256(clé, « horodatage.corps »)>, Idempotency-Key (recommandé).
 * Corps : { "events": [ { "title", "victim", "victim_domain", "posted_at", "data_classes", "indicators": [...] } ] }.
 * Les secrets éventuels (mots de passe, cookies) ne sont jamais conservés : seule leur présence est notée.
 */
export async function POST(req: Request) {
  const len = Number(req.headers.get("content-length") || 0);
  if (len > LIMITS.bodyBytes) return NextResponse.json({ error: "Corps trop volumineux (2 Mo au plus)." }, { status: 413 });
  const raw = await req.text();
  if (raw.length > LIMITS.bodyBytes) return NextResponse.json({ error: "Corps trop volumineux (2 Mo au plus)." }, { status: 413 });
  try {
    const src = await authenticateIngest(req.headers, raw);
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return NextResponse.json({ error: "JSON invalide." }, { status: 400 });
    }
    const r = await enqueue(src.id, req.headers.get("idempotency-key") ?? "", body);
    if (!r.duplicate) after(() => processQueue(10).catch((e) => console.error(`[fuites] traitement : ${e}`)));
    return NextResponse.json({ source: src.name, job: r.jobId, duplicate: r.duplicate, accepted: r.accepted, warnings: r.rejected }, { status: r.duplicate ? 200 : 202 });
  } catch (e) {
    if (e instanceof LeakError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error(`[fuites] ingestion : ${e instanceof Error ? e.message : e}`);
    return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
  }
}

import { after, NextResponse } from "next/server";
import { LIMITS } from "@/lib/patch/core";
import { agentServer } from "@/lib/patch/http";
import { agentSync, authenticateDevice, correlateDevice, PatchError, runPolicies } from "@/lib/patch/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/**
 * Synchronisation de l'agent (chaque minute) : comptes rendus des tâches, inventaire (toutes les 4 heures ou sur
 * demande), puis tâches signées à exécuter et, si besoin, nouvelle version de l'agent.
 * En-têtes : Authorization: Bearer <clé de l'équipement>, X-VQ-Timestamp, X-VQ-Signature: sha256=<HMAC(clé, « horodatage.corps »)>.
 * La corrélation avec les CVE est faite après la réponse (elle peut interroger la NVD et OSV).
 */
export async function POST(req: Request) {
  if (Number(req.headers.get("content-length") || 0) > LIMITS.bodyBytes) return NextResponse.json({ error: "Corps trop volumineux." }, { status: 413 });
  const raw = await req.text();
  if (raw.length > LIMITS.bodyBytes) return NextResponse.json({ error: "Corps trop volumineux." }, { status: 413 });
  try {
    const device = await authenticateDevice(req.headers, raw);
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(raw);
    } catch {
      return NextResponse.json({ error: "JSON invalide." }, { status: 400 });
    }
    const key = (req.headers.get("authorization") ?? "").slice(7).trim();
    const { response, correlate } = await agentSync(device, key, body, agentServer(req));
    if (correlate) {
      after(async () => {
        try {
          await correlateDevice(device.id);
          await runPolicies(device.orgId);
        } catch (e) {
          console.error(`[parc] corrélation ${device.id} : ${e instanceof Error ? e.message : e}`);
        }
      });
    }
    return NextResponse.json(response, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    if (e instanceof PatchError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error(`[parc] synchronisation : ${e instanceof Error ? e.message : e}`);
    return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
  }
}

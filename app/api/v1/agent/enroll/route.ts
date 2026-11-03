import { NextResponse } from "next/server";
import { enrollDevice, PatchError, POLL_SECONDS } from "@/lib/patch/store";

export const dynamic = "force-dynamic";

/**
 * Enrôlement d'une machine par l'agent : { token, machineId, hostname, os, agentVersion }.
 * Renvoie l'identifiant de l'équipement et sa clé (remise une seule fois, jamais stockée).
 */
export async function POST(req: Request) {
  if (Number(req.headers.get("content-length") || 0) > 200_000) return NextResponse.json({ error: "Corps trop volumineux." }, { status: 413 });
  const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body !== "object") return NextResponse.json({ error: "JSON attendu." }, { status: 400 });
  try {
    const r = await enrollDevice(body);
    return NextResponse.json({ ...r, pollSeconds: POLL_SECONDS }, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    if (e instanceof PatchError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error(`[parc] enrôlement : ${e instanceof Error ? e.message : e}`);
    return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
  }
}

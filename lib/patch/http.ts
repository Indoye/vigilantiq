/** Parc & correctifs — aides communes aux routes de la console et de l'agent. */
import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { PatchError } from "./store.ts";

export async function userOr(): Promise<{ id: string; email: string } | NextResponse> {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Connectez-vous pour gérer votre parc." }, { status: 401 });
  return { id: s.user.id, email: s.user.email };
}

export function fail(e: unknown) {
  if (e instanceof PatchError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error(`[parc] ${e instanceof Error ? e.message : e}`);
  return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
}

export const noStore = { headers: { "Cache-Control": "private, no-store" } };

/** Adresse que l'agent doit contacter : domaine de production s'il est configuré, sinon celle de la requête. */
export function agentServer(req: Request): string {
  const env = process.env.APP_URL || process.env.BETTER_AUTH_URL;
  return (env || new URL(req.url).origin).replace(/\/+$/, "");
}

export async function readJson(req: Request): Promise<Record<string, unknown>> {
  const b = await req.json().catch(() => null);
  return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : {};
}

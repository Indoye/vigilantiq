/** Parc & correctifs — aides communes aux routes de la console et de l'agent. */
import { NextResponse } from "next/server";
import { requireTenant, type Role } from "@/lib/tenant";
import { PatchError } from "./store.ts";

/**
 * Contexte de l'organisation (multitenant) avec un rôle minimal : « id » est l'identifiant de l'organisation,
 * clé de toutes les données ; « email » sert de trace de l'auteur dans le journal.
 */
export async function userOr(min: Role = "viewer"): Promise<{ id: string; email: string; userId: string; role: Role } | NextResponse> {
  const t = await requireTenant(min, "Connectez-vous pour gérer votre parc.");
  if (t instanceof NextResponse) return t;
  return { id: t.orgId, email: t.email, userId: t.userId, role: t.role };
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

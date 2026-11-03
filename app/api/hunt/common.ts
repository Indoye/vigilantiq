import { NextResponse } from "next/server";
import { requireTenant, type Role } from "@/lib/tenant";
import { HuntError } from "@/lib/hunt/store";

/**
 * Contexte de l'organisation (multitenant) avec un rôle minimal : « id » est l'identifiant de l'organisation,
 * clé de toutes les données ; « email » sert de trace de l'auteur dans le journal.
 */
export async function userOr(min: Role = "viewer"): Promise<{ id: string; email: string; userId: string; role: Role } | NextResponse> {
  const t = await requireTenant(min, "Connectez-vous pour utiliser le Threat Hunting.");
  if (t instanceof NextResponse) return t;
  return { id: t.orgId, email: t.email, userId: t.userId, role: t.role };
}

export function fail(e: unknown) {
  if (e instanceof HuntError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error(`[chasse] ${e instanceof Error ? e.message : e}`);
  return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
}

export const noStore = { headers: { "Cache-Control": "private, no-store" } };

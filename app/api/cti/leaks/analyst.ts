import { NextResponse } from "next/server";
import { isAnalyst, LeakError, type LeakScope } from "@/lib/cti/leakstore";
import { requireTenant, type Role } from "@/lib/tenant";

/**
 * Portée des fuites :
 * - « ?portee=plateforme » : base commune, réservée aux analystes de la plateforme (VIGILANTIQ_ANALYSTS) ;
 * - sinon : sources et événements privés de l'organisation, selon le rôle (analyste pour qualifier, admin pour les sources).
 */
export async function analystOr(req: Request, min: Role = "analyst"): Promise<{ email: string; scope: LeakScope } | NextResponse> {
  const platform = new URL(req.url).searchParams.get("portee") === "plateforme";
  const t = await requireTenant(platform ? "viewer" : min);
  if (t instanceof NextResponse) return t;
  if (platform && !isAnalyst(t.email)) return NextResponse.json({ error: "Base commune réservée aux analystes de la plateforme." }, { status: 403 });
  return { email: t.email, scope: platform ? null : t.orgId };
}

export function fail(e: unknown) {
  if (e instanceof LeakError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error(`[fuites] ${e instanceof Error ? e.message : e}`);
  return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
}

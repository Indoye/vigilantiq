import { NextResponse } from "next/server";
import { scAllowed, ScError } from "@/lib/securitycontext";
import { requireTenant, type Role, type Tenant } from "@/lib/tenant";

/** Organisation connectée, avec l'intégration SecurityContext ouverte pour elle. */
export async function scTenant(min: Role = "viewer"): Promise<Tenant | NextResponse> {
  const t = await requireTenant(min);
  if (t instanceof NextResponse) return t;
  if (!scAllowed(t.email)) return NextResponse.json({ error: "L’intégration SecurityContext n’est pas activée pour votre organisation." }, { status: 403 });
  return t;
}

export function scFail(e: unknown) {
  if (e instanceof ScError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error("[securitycontext]", e);
  return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
}

export const noStore = { headers: { "Cache-Control": "private, no-store" } };

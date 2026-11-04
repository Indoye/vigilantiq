import { NextResponse } from "next/server";
import { isAnalyst } from "@/lib/cti/leakstore";
import { DarkwebError } from "@/lib/darkweb/store";
import { SearchError } from "@/lib/darkweb/search";
import { UnsafeUrlError } from "@/lib/netguard";
import { requireTenant, TenantError, type Role, type Tenant } from "@/lib/tenant";

export const body = async (req: Request) => ((await req.json().catch(() => null)) ?? {}) as Record<string, unknown>;

/** Collecte (sources, runs) : réservée aux analystes de la plateforme (VIGILANTIQ_ANALYSTS). */
export async function platformAnalyst(): Promise<Tenant | NextResponse> {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  if (!isAnalyst(t.email)) return NextResponse.json({ error: "Réservé aux analystes de la plateforme." }, { status: 403 });
  return t;
}

export const tenant = (min: Role) => requireTenant(min);

export function fail(e: unknown) {
  if (e instanceof DarkwebError || e instanceof TenantError) return NextResponse.json({ error: e.message }, { status: e.status });
  if (e instanceof SearchError || e instanceof UnsafeUrlError) return NextResponse.json({ error: e.message }, { status: 502 });
  console.error(`[dark web] ${e instanceof Error ? e.message : e}`);
  return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
}

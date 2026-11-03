import { NextResponse } from "next/server";
import { requireTenant } from "@/lib/tenant";
import { checkAccounts } from "@/lib/cti/accountstore";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Contrôle le lot suivant d'adresses ; l'interface rappelle cette route tant qu'il en reste. */
export async function POST() {
  const s = await requireTenant("analyst");
  if (s instanceof NextResponse) return s;
  return NextResponse.json(await checkAccounts(s.orgId, 12));
}

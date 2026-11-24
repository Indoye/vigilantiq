import { NextResponse } from "next/server";
import { ATTRIBUTION, cveContext } from "@/lib/securitycontext";
import { noStore, scFail, scTenant } from "../../common";

export const dynamic = "force-dynamic";

/** Contexte SecurityContext d'une CVE (exploitation, exploits publics, Nuclei, exposition, produits). */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const t = await scTenant();
  if (t instanceof NextResponse) return t;
  try {
    const { id } = await params;
    const ctx = await cveContext(id.toUpperCase());
    return NextResponse.json({ context: ctx, source: ATTRIBUTION }, noStore);
  } catch (e) {
    return scFail(e);
  }
}

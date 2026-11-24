import { NextResponse } from "next/server";
import { escalationsByCve } from "@/lib/sc-core";
import { ATTRIBUTION, escalations } from "@/lib/securitycontext";
import { noStore, scFail, scTenant } from "../common";

export const dynamic = "force-dynamic";

/** Escalades des 30 derniers jours : nouvellement exploitées (CISA, VulnCheck), premier exploit public, Nuclei, passées critiques. */
export async function GET() {
  const t = await scTenant();
  if (t instanceof NextResponse) return t;
  try {
    const items = await escalations();
    return NextResponse.json({ items, byCve: escalationsByCve(items), source: ATTRIBUTION }, noStore);
  } catch (e) {
    return scFail(e);
  }
}

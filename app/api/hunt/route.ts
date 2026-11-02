import { NextResponse } from "next/server";
import { aiAgentConfig } from "@/lib/hunt/agent";
import { overview } from "@/lib/hunt/store";
import { fail, noStore, userOr } from "./common";

export const dynamic = "force-dynamic";

/** Vue d'ensemble : équipements, détections, connecteur, IOC disponibles, historique des chasses et enquêtes. */
export async function GET() {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    const ai = aiAgentConfig();
    return NextResponse.json({ ...(await overview(u.id)), ai: { configured: ai.configured, provider: ai.configured ? ai.provider : null, model: ai.configured ? ai.model : null } }, noStore);
  } catch (e) {
    return fail(e);
  }
}

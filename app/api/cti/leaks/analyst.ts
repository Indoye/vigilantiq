import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { isAnalyst, LeakError } from "@/lib/cti/leakstore";

/** Session d'un analyste (VIGILANTIQ_ANALYSTS), sinon réponse d'erreur. */
export async function analystOr(): Promise<{ email: string } | NextResponse> {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Connectez-vous." }, { status: 401 });
  if (!isAnalyst(s.user.email)) return NextResponse.json({ error: "Réservé aux analystes." }, { status: 403 });
  return { email: s.user.email };
}

export function fail(e: unknown) {
  if (e instanceof LeakError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error(`[fuites] ${e instanceof Error ? e.message : e}`);
  return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
}

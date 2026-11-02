import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { HuntError } from "@/lib/hunt/store";

export async function userOr(): Promise<{ id: string; email: string } | NextResponse> {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Connectez-vous pour utiliser le Threat Hunting." }, { status: 401 });
  return { id: s.user.id, email: s.user.email };
}

export function fail(e: unknown) {
  if (e instanceof HuntError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error(`[chasse] ${e instanceof Error ? e.message : e}`);
  return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
}

export const noStore = { headers: { "Cache-Control": "private, no-store" } };

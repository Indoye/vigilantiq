import { NextResponse } from "next/server";
import { TenantError } from "@/lib/tenant";

export const body = async (req: Request) => ((await req.json().catch(() => null)) ?? {}) as Record<string, unknown>;
export const str = (v: unknown) => (typeof v === "string" ? v : "");

export function fail(e: unknown) {
  if (e instanceof TenantError) return NextResponse.json({ error: e.message }, { status: e.status });
  console.error(`[organisation] ${e instanceof Error ? e.message : e}`);
  return NextResponse.json({ error: "Erreur interne." }, { status: 500 });
}

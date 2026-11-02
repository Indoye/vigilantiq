import { NextResponse } from "next/server";
import { fail, noStore, userOr } from "@/lib/patch/http";
import { overview } from "@/lib/patch/store";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Vue d'ensemble du parc : indicateurs, tendance sur 90 jours, équipements, déploiements, politiques, journal. */
export async function GET() {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json(await overview(u.id), noStore);
  } catch (e) {
    return fail(e);
  }
}

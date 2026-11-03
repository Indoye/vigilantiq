import { NextResponse } from "next/server";
import { listForAnalyst, manualEntry, qualify, queueStats, statusCounts } from "@/lib/cti/leakstore";
import { analystOr, fail } from "../analyst";

export const dynamic = "force-dynamic";

/** Événements à qualifier (analystes). */
export async function GET(req: Request) {
  const a = await analystOr(req);
  if (a instanceof NextResponse) return a;
  const u = new URL(req.url);
  try {
    const [events, queue, counts] = await Promise.all([listForAnalyst(a.scope, u.searchParams.get("statut"), (u.searchParams.get("q") ?? "").slice(0, 80)), queueStats(a.scope), statusCounts(a.scope)]);
    return NextResponse.json({ events, queue, counts }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (e) {
    return fail(e);
  }
}

/** Qualification : { id, status?, reliability?, note? } */
export async function PATCH(req: Request) {
  const a = await analystOr(req);
  if (a instanceof NextResponse) return a;
  const b = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  const id = Number(b?.id);
  if (!b || !Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    return NextResponse.json({ ok: true, alerts: await qualify(id, b, a.email, a.scope) });
  } catch (e) {
    return fail(e);
  }
}

/** Saisie manuelle d'une fuite repérée par un analyste (même format que l'API d'ingestion). */
export async function POST(req: Request) {
  const a = await analystOr(req);
  if (a instanceof NextResponse) return a;
  const b = await req.json().catch(() => null);
  if (!b) return NextResponse.json({ error: "JSON invalide." }, { status: 400 });
  try {
    return NextResponse.json(await manualEntry(b, a.email, a.scope));
  } catch (e) {
    return fail(e);
  }
}

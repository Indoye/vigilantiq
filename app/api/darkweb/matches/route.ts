import { NextResponse } from "next/server";
import { listMatches, setMatchStatus } from "@/lib/darkweb/store";
import { body, fail, tenant } from "../common";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const t = await tenant("viewer");
  if (t instanceof NextResponse) return t;
  const sp = new URL(req.url).searchParams;
  const rows = await listMatches(t.orgId, { status: sp.get("statut") ?? undefined, patternId: Number(sp.get("motif")) || undefined });
  return NextResponse.json(
    { matches: rows.map((r) => ({ ...r.m, pattern: r.name, kind: r.kind, severity: r.severity })) },
    { headers: { "Cache-Control": "private, no-store" } },
  );
}

/** { id, status: nouvelle | traitee | faux_positif } */
export async function PATCH(req: Request) {
  const t = await tenant("analyst");
  if (t instanceof NextResponse) return t;
  try {
    const b = await body(req);
    await setMatchStatus(t.orgId, Number(b.id), String(b.status));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

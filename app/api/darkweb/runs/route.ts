import { NextResponse } from "next/server";
import { advanceRun, listRuns, startRun } from "@/lib/darkweb/store";
import { body, fail, platformAnalyst } from "../common";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

export async function GET() {
  const t = await platformAnalyst();
  if (t instanceof NextResponse) return t;
  const rows = await listRuns();
  return NextResponse.json({ runs: rows.map((r) => ({ ...r.run, label: r.label })) }, { headers: { "Cache-Control": "private, no-store" } });
}

/** { sourceId } : lance une collecte maintenant — { runId } : récupère et ingère ce qu'elle a produit. */
export async function POST(req: Request) {
  const t = await platformAnalyst();
  if (t instanceof NextResponse) return t;
  try {
    const b = await body(req);
    if (b.runId) return NextResponse.json(await advanceRun(Number(b.runId), Date.now() + 90_000));
    return NextResponse.json({ id: await startRun(Number(b.sourceId), "manuel") }, { status: 201 });
  } catch (e) {
    return fail(e);
  }
}

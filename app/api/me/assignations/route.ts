import { NextResponse } from "next/server";
import { assign, assignments } from "@/lib/teamwork";
import { requireTenant, TenantError } from "@/lib/tenant";

export const dynamic = "force-dynamic";

/** Responsables des CVE de l'organisation : { CVE-…: { userId, name } }. */
export async function GET() {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  return NextResponse.json({ me: t.userId, items: await assignments(t.orgId) }, { headers: { "Cache-Control": "private, no-store" } });
}

/** Actions groupées : { cveIds: string[], assigneeId: string | null } */
export async function PUT(req: Request) {
  const t = await requireTenant("analyst");
  if (t instanceof NextResponse) return t;
  try {
    const b = (await req.json().catch(() => ({}))) as { cveIds?: unknown; assigneeId?: unknown };
    const ids = Array.isArray(b.cveIds) ? b.cveIds.filter((x): x is string => typeof x === "string" && /^CVE-\d{4}-\d{4,}$/i.test(x)).map((x) => x.toUpperCase()) : [];
    await assign(t, ids, typeof b.assigneeId === "string" && b.assigneeId ? b.assigneeId : null);
    return NextResponse.json({ ok: true, items: await assignments(t.orgId) });
  } catch (e) {
    return e instanceof TenantError ? NextResponse.json({ error: e.message }, { status: e.status }) : NextResponse.json({ error: "Erreur interne." }, { status: 500 });
  }
}

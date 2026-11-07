import { NextResponse } from "next/server";
import { CVE_ID_RE } from "@/lib/detail";
import { addComment, assign, deleteComment, teamInfo } from "@/lib/teamwork";
import { requireTenant, TenantError } from "@/lib/tenant";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ id: string }> };

const fail = (e: unknown) =>
  e instanceof TenantError ? NextResponse.json({ error: e.message }, { status: e.status }) : (console.error(`[équipe] ${e}`), NextResponse.json({ error: "Erreur interne." }, { status: 500 }));

async function cve(ctx: Ctx) {
  const id = (await ctx.params).id.toUpperCase();
  return CVE_ID_RE.test(id) ? id : null;
}

/** Responsable, commentaires, membres et équipements du parc touchés. */
export async function GET(_req: Request, ctx: Ctx) {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  const id = await cve(ctx);
  if (!id) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  return NextResponse.json(await teamInfo(t, id), { headers: { "Cache-Control": "private, no-store" } });
}

/** { assigneeId: string | null } */
export async function PUT(req: Request, ctx: Ctx) {
  const t = await requireTenant("analyst");
  if (t instanceof NextResponse) return t;
  const id = await cve(ctx);
  if (!id) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  try {
    const b = (await req.json().catch(() => ({}))) as { assigneeId?: unknown };
    await assign(t, [id], typeof b.assigneeId === "string" && b.assigneeId ? b.assigneeId : null);
    return NextResponse.json(await teamInfo(t, id));
  } catch (e) {
    return fail(e);
  }
}

/** { body } */
export async function POST(req: Request, ctx: Ctx) {
  const t = await requireTenant("analyst");
  if (t instanceof NextResponse) return t;
  const id = await cve(ctx);
  if (!id) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  try {
    const b = (await req.json().catch(() => ({}))) as { body?: unknown };
    await addComment(t, id, String(b.body ?? ""));
    return NextResponse.json(await teamInfo(t, id), { status: 201 });
  } catch (e) {
    return fail(e);
  }
}

/** ?commentaire=… */
export async function DELETE(req: Request, ctx: Ctx) {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  const id = await cve(ctx);
  if (!id) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  try {
    await deleteComment(t, Number(new URL(req.url).searchParams.get("commentaire")));
    return NextResponse.json(await teamInfo(t, id));
  } catch (e) {
    return fail(e);
  }
}

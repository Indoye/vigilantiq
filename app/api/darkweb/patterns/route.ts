import { NextResponse } from "next/server";
import { createPattern, listPatterns, removePattern, updatePattern } from "@/lib/darkweb/store";
import { body, fail, tenant } from "../common";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Motifs surveillés par l'organisation (jamais l'adresse d'un motif e-mail : seulement sa forme masquée). */
export async function GET() {
  const t = await tenant("viewer");
  if (t instanceof NextResponse) return t;
  const rows = await listPatterns(t.orgId);
  return NextResponse.json({ patterns: rows.map(({ value, ...p }) => ({ ...p, value: p.kind === "email" ? "" : value })) }, { headers: { "Cache-Control": "private, no-store" } });
}

/** { name, kind, value, severity } — recherche aussitôt dans le corpus déjà collecté. */
export async function POST(req: Request) {
  const t = await tenant("analyst");
  if (t instanceof NextResponse) return t;
  try {
    const r = await createPattern(t.orgId, t.email, await body(req));
    return NextResponse.json({ id: r.pattern.id, retro: r.retro }, { status: 201 });
  } catch (e) {
    return fail(e);
  }
}

/** { id, name?, severity?, active? } */
export async function PATCH(req: Request) {
  const t = await tenant("analyst");
  if (t instanceof NextResponse) return t;
  try {
    const b = await body(req);
    await updatePattern(t.orgId, Number(b.id), b);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

export async function DELETE(req: Request) {
  const t = await tenant("analyst");
  if (t instanceof NextResponse) return t;
  try {
    await removePattern(t.orgId, Number(new URL(req.url).searchParams.get("id")));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

import { NextResponse } from "next/server";
import { mispConfigured, taxiiConfigured } from "@/lib/cti/leakconnectors";
import { createSource, listSources, rotateKey, updateSource } from "@/lib/cti/leakstore";
import { analystOr, fail } from "../analyst";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const a = await analystOr(req, "admin");
  if (a instanceof NextResponse) return a;
  try {
    return NextResponse.json({ sources: await listSources(a.scope), connectors: a.scope ? null : { misp: mispConfigured(), taxii: taxiiConfigured() }, scope: a.scope ? "organisation" : "plateforme" }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (e) {
    return fail(e);
  }
}

/** Nouvelle source : la clé d'ingestion n'est affichée qu'une fois. */
export async function POST(req: Request) {
  const a = await analystOr(req, "admin");
  if (a instanceof NextResponse) return a;
  const b = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!b) return NextResponse.json({ error: "JSON invalide." }, { status: 400 });
  try {
    return NextResponse.json(await createSource(b, a.email, a.scope), { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    return fail(e);
  }
}

/** { id, active?, reliability?, name? } ou { id, rotate: true } (nouvelle clé). */
export async function PATCH(req: Request) {
  const a = await analystOr(req, "admin");
  if (a instanceof NextResponse) return a;
  const b = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  const id = Number(b?.id);
  if (!b || !Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    if (b.rotate === true) return NextResponse.json({ id, key: await rotateKey(id, a.scope) }, { headers: { "Cache-Control": "no-store" } });
    await updateSource(id, b, a.scope);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

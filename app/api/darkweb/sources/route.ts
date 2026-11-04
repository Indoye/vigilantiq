import { NextResponse } from "next/server";
import { createSource, deleteSource, listSources, updateSource } from "@/lib/darkweb/store";
import { body, fail, platformAnalyst } from "../common";

export const dynamic = "force-dynamic";

export async function GET() {
  const t = await platformAnalyst();
  if (t instanceof NextResponse) return t;
  return NextResponse.json({ sources: await listSources() }, { headers: { "Cache-Control": "private, no-store" } });
}

/** { label, url (.onion v3), keyword, maxDepth, maxPages } */
export async function POST(req: Request) {
  const t = await platformAnalyst();
  if (t instanceof NextResponse) return t;
  try {
    return NextResponse.json({ source: await createSource(await body(req), t.email) }, { status: 201 });
  } catch (e) {
    return fail(e);
  }
}

export async function PATCH(req: Request) {
  const t = await platformAnalyst();
  if (t instanceof NextResponse) return t;
  try {
    const b = await body(req);
    await updateSource(Number(b.id), b);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

export async function DELETE(req: Request) {
  const t = await platformAnalyst();
  if (t instanceof NextResponse) return t;
  try {
    await deleteSource(Number(new URL(req.url).searchParams.get("id")));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

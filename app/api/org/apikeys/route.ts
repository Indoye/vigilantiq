import { NextResponse } from "next/server";
import { createApiKey, revokeApiKey } from "@/lib/apiauth";
import { requireTenant } from "@/lib/tenant";
import { body, fail, str } from "../common";

export const dynamic = "force-dynamic";

/** { name, scope: "lecture" | "ecriture" } — la clé n'est renvoyée qu'une seule fois. */
export async function POST(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  try {
    const b = await body(req);
    return NextResponse.json(await createApiKey(t, str(b.name), str(b.scope)), { status: 201, headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    return fail(e);
  }
}

/** ?id=… */
export async function DELETE(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  try {
    await revokeApiKey(t, Number(new URL(req.url).searchParams.get("id")));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

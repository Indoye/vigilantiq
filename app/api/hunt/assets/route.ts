import { NextResponse } from "next/server";
import { INSTALL, powershellAgent, shellAgent } from "@/lib/hunt/scripts";
import { createAsset, deleteAsset, rotateAssetKey } from "@/lib/hunt/store";
import { fail, noStore, userOr } from "../common";

export const dynamic = "force-dynamic";

const kit = (req: Request, key: string) => {
  const url = `${new URL(req.url).origin}/api/v1/telemetrie`;
  return { key, scripts: { windows: powershellAgent(url, key), unix: shellAgent(url, key) }, install: INSTALL };
};

/** Nouvel équipement : clé et scripts d'agent renvoyés une seule fois. */
export async function POST(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const b = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  try {
    const { id, key } = await createAsset(u.id, b ?? {});
    return NextResponse.json({ id, ...kit(req, key) }, noStore);
  } catch (e) {
    return fail(e);
  }
}

/** { id, rotate: true } : nouvelle clé (l'ancienne cesse de fonctionner). */
export async function PATCH(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const b = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  const id = Number(b?.id);
  if (!Number.isInteger(id) || b?.rotate !== true) return NextResponse.json({ error: "Requête invalide." }, { status: 400 });
  try {
    return NextResponse.json({ id, ...kit(req, await rotateAssetKey(u.id, id)) }, noStore);
  } catch (e) {
    return fail(e);
  }
}

export async function DELETE(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const id = Number(new URL(req.url).searchParams.get("id"));
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    await deleteAsset(u.id, id);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

import { NextResponse } from "next/server";
import { setFindingStatus } from "@/lib/hunt/store";
import { fail, userOr } from "../common";

export const dynamic = "force-dynamic";

/** { id, status } : nouveau | en_cours | resolu | faux_positif */
export async function PATCH(req: Request) {
  const u = await userOr("analyst");
  if (u instanceof NextResponse) return u;
  const b = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  const id = Number(b?.id);
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    await setFindingStatus(u.id, id, String(b?.status ?? ""));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

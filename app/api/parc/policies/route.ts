import { NextResponse } from "next/server";
import { fail, noStore, readJson, userOr } from "@/lib/patch/http";
import { deletePolicy, listPolicies, runPolicies, savePolicy } from "@/lib/patch/store";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET() {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json({ items: await listPolicies(u.id) }, noStore);
  } catch (e) {
    return fail(e);
  }
}

/** Création ({ … }) ou modification ({ id, … }) ; les politiques sont ensuite appliquées aussitôt. */
export async function POST(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const b = await readJson(req);
  try {
    const id = await savePolicy(u.id, u.email, Number.isInteger(Number(b.id)) && Number(b.id) > 0 ? Number(b.id) : null, b);
    const deployments = await runPolicies(u.id);
    return NextResponse.json({ id, deployments });
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
    await deletePolicy(u.id, u.email, id);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

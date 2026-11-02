import { NextResponse } from "next/server";
import { deleteSiem, getSiem, pullSiem, saveSiem } from "@/lib/hunt/store";
import { fail, noStore, userOr } from "../common";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

export async function GET() {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json({ siem: await getSiem(u.id) }, noStore);
  } catch (e) {
    return fail(e);
  }
}

/** Enregistre le connecteur (identifiants chiffrés), puis tente une première collecte. */
export async function PUT(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const b = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  try {
    await saveSiem(u.id, b ?? {});
    const pull = await pullSiem(u.id).catch((e) => ({ error: e instanceof Error ? e.message : String(e) }));
    return NextResponse.json({ siem: await getSiem(u.id), pull }, noStore);
  } catch (e) {
    return fail(e);
  }
}

/** Collecte immédiate. */
export async function POST() {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json({ pull: await pullSiem(u.id), siem: await getSiem(u.id) }, noStore);
  } catch (e) {
    return fail(e);
  }
}

export async function DELETE() {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    await deleteSiem(u.id);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

import { NextResponse } from "next/server";
import { dbConfigured } from "@/db";
import { currentSession } from "@/lib/auth";
import { addWatch, listAlerts, listWatch, MAX_WATCH, removeWatch, WatchError } from "@/lib/cti/store";

export const dynamic = "force-dynamic";

const unauth = () => NextResponse.json({ error: "Connectez-vous pour gérer votre surveillance." }, { status: 401 });

/** Liste de surveillance et alertes de l'utilisateur connecté. */
export async function GET() {
  const s = await currentSession();
  if (!s) return unauth();
  if (!dbConfigured()) return NextResponse.json({ error: "Base de données non configurée." }, { status: 503 });
  const [items, alerts] = await Promise.all([listWatch(s.user.id), listAlerts(s.user.id)]);
  return NextResponse.json({ items, alerts, max: MAX_WATCH, email: s.user.emailVerified ? s.user.email : null });
}

export async function POST(req: Request) {
  const s = await currentSession();
  if (!s) return unauth();
  const body = (await req.json().catch(() => null)) as { kind?: unknown; value?: unknown } | null;
  try {
    const item = await addWatch(s.user.id, String(body?.kind ?? ""), String(body?.value ?? ""));
    return NextResponse.json(item, { status: 201 });
  } catch (e) {
    if (e instanceof WatchError) return NextResponse.json({ error: e.message }, { status: 400 });
    throw e;
  }
}

export async function DELETE(req: Request) {
  const s = await currentSession();
  if (!s) return unauth();
  const id = Number(new URL(req.url).searchParams.get("id"));
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  return (await removeWatch(s.user.id, id)) ? NextResponse.json({ ok: true }) : NextResponse.json({ error: "Introuvable." }, { status: 404 });
}

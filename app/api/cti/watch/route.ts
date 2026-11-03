import { after, NextResponse } from "next/server";
import { dbConfigured } from "@/db";
import { requireTenant } from "@/lib/tenant";
import { recorrelateRecent } from "@/lib/cti/leakstore";
import { addWatch, listAlerts, listWatch, MAX_WATCH, removeWatch, WatchError } from "@/lib/cti/store";

export const dynamic = "force-dynamic";

const unauth = () => NextResponse.json({ error: "Connectez-vous pour gérer votre surveillance." }, { status: 401 });

/** Liste de surveillance et alertes de l'utilisateur connecté. */
export async function GET() {
  const s = await requireTenant("viewer");
  if (s instanceof NextResponse) return s;
  if (!dbConfigured()) return NextResponse.json({ error: "Base de données non configurée." }, { status: 503 });
  const [items, alerts] = await Promise.all([listWatch(s.orgId), listAlerts(s.orgId)]);
  return NextResponse.json({ items, alerts, max: MAX_WATCH, email: s.user.emailVerified ? s.email : null });
}

export async function POST(req: Request) {
  const s = await requireTenant("analyst");
  if (s instanceof NextResponse) return s;
  const body = (await req.json().catch(() => null)) as { kind?: unknown; value?: unknown } | null;
  try {
    const item = await addWatch(s.orgId, String(body?.kind ?? ""), String(body?.value ?? ""));
    // Nouvelle marque : rapprochement avec les fuites déjà connues
    if (item.kind === "brand") after(() => recorrelateRecent().catch((e) => console.error(`[fuites] rattrapage : ${e}`)));
    return NextResponse.json(item, { status: 201 });
  } catch (e) {
    if (e instanceof WatchError) return NextResponse.json({ error: e.message }, { status: 400 });
    throw e;
  }
}

export async function DELETE(req: Request) {
  const s = await requireTenant("analyst");
  if (s instanceof NextResponse) return s;
  const id = Number(new URL(req.url).searchParams.get("id"));
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  return (await removeWatch(s.orgId, id)) ? NextResponse.json({ ok: true }) : NextResponse.json({ error: "Introuvable." }, { status: 404 });
}

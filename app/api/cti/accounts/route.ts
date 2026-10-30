import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { AccountError, addAccounts, listAccounts, MAX_ACCOUNTS, removeAccounts } from "@/lib/cti/accountstore";

export const dynamic = "force-dynamic";

const unauth = () => NextResponse.json({ error: "Connectez-vous pour gérer vos comptes surveillés." }, { status: 401 });

/** Comptes surveillés de l'utilisateur et ce qui a été trouvé pour chacun (métadonnées, sans mot de passe). */
export async function GET() {
  const s = await currentSession();
  if (!s) return unauth();
  return NextResponse.json({ max: MAX_ACCOUNTS, items: await listAccounts(s.user.id) }, { headers: { "Cache-Control": "no-store" } });
}

/** Ajoute des adresses (texte libre, CSV…) appartenant à un domaine vérifié. */
export async function POST(req: Request) {
  const s = await currentSession();
  if (!s) return unauth();
  const body = (await req.json().catch(() => null)) as { text?: unknown } | null;
  const text = String(body?.text ?? "").slice(0, 200_000);
  try {
    return NextResponse.json(await addAccounts(s.user.id, text));
  } catch (e) {
    if (e instanceof AccountError) return NextResponse.json({ error: e.message }, { status: 400 });
    throw e;
  }
}

export async function DELETE(req: Request) {
  const s = await currentSession();
  if (!s) return unauth();
  const body = (await req.json().catch(() => null)) as { ids?: unknown } | null;
  const ids = body?.ids === "all" ? "all" : Array.isArray(body?.ids) ? body!.ids.filter((x): x is number => Number.isInteger(x)).slice(0, 1000) : null;
  if (!ids) return NextResponse.json({ error: "Liste invalide." }, { status: 400 });
  await removeAccounts(s.user.id, ids);
  return NextResponse.json({ ok: true });
}

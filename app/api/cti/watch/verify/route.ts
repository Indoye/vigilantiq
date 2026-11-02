import { after, NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { AccountError, verifyDomain } from "@/lib/cti/accountstore";
import { recorrelateRecent } from "@/lib/cti/leakstore";

export const dynamic = "force-dynamic";

/** Vérifie la propriété d'un domaine surveillé (enregistrement DNS TXT « vigilantiq-verification=… »). */
export async function POST(req: Request) {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Connectez-vous pour vérifier un domaine." }, { status: 401 });
  const body = (await req.json().catch(() => null)) as { id?: unknown } | null;
  const id = Number(body?.id);
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    const r = await verifyDomain(s.user.id, id);
    // Domaine désormais vérifié : rapprochement avec les fuites déjà connues (90 derniers jours)
    if (r.verified) after(() => recorrelateRecent().catch((e) => console.error(`[fuites] rattrapage : ${e}`)));
    return NextResponse.json(r);
  } catch (e) {
    if (e instanceof AccountError) return NextResponse.json({ error: e.message }, { status: 400 });
    return NextResponse.json({ error: `Vérification DNS impossible : ${e instanceof Error ? e.message : e}` }, { status: 502 });
  }
}

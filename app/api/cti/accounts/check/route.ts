import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { checkAccounts } from "@/lib/cti/accountstore";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Contrôle le lot suivant d'adresses ; l'interface rappelle cette route tant qu'il en reste. */
export async function POST() {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Connectez-vous pour lancer le contrôle." }, { status: 401 });
  return NextResponse.json(await checkAccounts(s.user.id, 12));
}

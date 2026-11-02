import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { listUserLeaks } from "@/lib/cti/leakstore";

export const dynamic = "force-dynamic";

/** Fuites du darkweb rapprochées de la liste de surveillance de l'utilisateur. */
export async function GET() {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Connectez-vous pour voir vos fuites." }, { status: 401 });
  return NextResponse.json({ leaks: await listUserLeaks(s.user.id) }, { headers: { "Cache-Control": "private, no-store" } });
}

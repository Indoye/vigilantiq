import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { parseSettingsPatch, updateSettings } from "@/lib/userdata";

export const dynamic = "force-dynamic";

/** Met à jour la stack ou les préférences de digest. */
export async function PATCH(req: Request) {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Session expirée. Reconnectez-vous." }, { status: 401 });
  const patch = parseSettingsPatch(await req.json().catch(() => null));
  if (!patch) return NextResponse.json({ error: "Préférences invalides." }, { status: 400 });
  return NextResponse.json(await updateSettings(s.user.id, patch));
}

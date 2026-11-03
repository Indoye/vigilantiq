import { NextResponse } from "next/server";
import { can, requireTenant } from "@/lib/tenant";
import { parseSettingsPatch, updateSettings } from "@/lib/userdata";

export const dynamic = "force-dynamic";

/** Met à jour la stack ou les préférences de digest. */
export async function PATCH(req: Request) {
  const s = await requireTenant("viewer");
  if (s instanceof NextResponse) return s;
  const patch = parseSettingsPatch(await req.json().catch(() => null));
  if (!patch) return NextResponse.json({ error: "Préférences invalides." }, { status: 400 });
  // La stack est commune à l'organisation : sa modification est réservée aux analystes et au-delà.
  if (patch.stack !== undefined && !can(s.role, "analyst")) return NextResponse.json({ error: "Modifier la stack de l’organisation est réservé aux analystes et administrateurs." }, { status: 403 });
  return NextResponse.json(await updateSettings(s.userId, s.orgId, patch));
}

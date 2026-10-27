import { NextResponse } from "next/server";
import { authorize, unauthorized } from "@/lib/apiauth";
import { CVE_ID_RE, getCveDetail } from "@/lib/detail";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Fiche complète d'une CVE, avec plan de remédiation et codes d'exploitation connus. */
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  if (!(await authorize(req))) return unauthorized();
  const id = (await ctx.params).id.toUpperCase();
  if (!CVE_ID_RE.test(id)) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  const detail = await getCveDetail(id);
  if (!detail) return NextResponse.json({ error: `${id} introuvable dans NVD et CVE.org` }, { status: 404 });
  return NextResponse.json(detail);
}

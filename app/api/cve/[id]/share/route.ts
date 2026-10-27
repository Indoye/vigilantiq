import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
import { CVE_ID_RE } from "@/lib/detail";
import { sharePath } from "@/lib/share";
import { appUrl } from "@/lib/ticketstore";

export const dynamic = "force-dynamic";

/** Lien public signé d'une CVE, délivré aux seuls utilisateurs connectés. */
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  if (!(await currentSession())) return NextResponse.json({ error: "Session expirée. Reconnectez-vous." }, { status: 401 });
  const id = (await ctx.params).id.toUpperCase();
  if (!CVE_ID_RE.test(id)) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  const path = sharePath(id);
  if (!path) return NextResponse.json({ error: "Partage indisponible : secret de l’application non configuré." }, { status: 503 });
  // Adresse de production de préférence (le lien doit rester valable), sinon celle de la requête (local).
  const configured = process.env.APP_URL || process.env.BETTER_AUTH_URL || process.env.VERCEL_PROJECT_PRODUCTION_URL;
  const origin = configured ? appUrl() : new URL(req.url).origin;
  return NextResponse.json({ url: `${origin}${path}` });
}

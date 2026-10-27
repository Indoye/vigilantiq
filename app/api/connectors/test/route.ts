import { NextResponse } from "next/server";
import { isAdmin } from "@/lib/apiauth";
import { currentSession } from "@/lib/auth";
import { CONNECTOR_IDS, testConnector, type ConnectorId } from "@/lib/connectors";

export const dynamic = "force-dynamic";

/** Vérifie les identifiants d'un connecteur (réservé aux administrateurs si ADMIN_EMAILS est défini). */
export async function POST(req: Request) {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Session expirée. Reconnectez-vous." }, { status: 401 });
  if (!isAdmin(s.user.email)) return NextResponse.json({ error: "Réservé aux administrateurs." }, { status: 403 });
  let id: unknown;
  try {
    id = ((await req.json()) as { connector?: unknown }).connector;
  } catch {
    id = undefined;
  }
  if (typeof id !== "string" || !(CONNECTOR_IDS as string[]).includes(id)) {
    return NextResponse.json({ error: "Connecteur inconnu." }, { status: 400 });
  }
  try {
    return NextResponse.json({ ok: true, message: await testConnector(id as ConnectorId) });
  } catch (e) {
    return NextResponse.json({ ok: false, message: e instanceof Error ? e.message : String(e) }, { status: 502 });
  }
}

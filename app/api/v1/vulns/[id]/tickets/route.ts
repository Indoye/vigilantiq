import { NextResponse } from "next/server";
import { authorize, unauthorized } from "@/lib/apiauth";
import { CONNECTOR_IDS, connectorInfo, type ConnectorId } from "@/lib/connectors";
import { CVE_ID_RE, getCveDetail } from "@/lib/detail";
import { AlreadySentError, appUrl, sendAndRecord, ticketsFor } from "@/lib/ticketstore";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  if (!(await authorize(req))) return unauthorized();
  const id = (await ctx.params).id.toUpperCase();
  if (!CVE_ID_RE.test(id)) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  return NextResponse.json({ cve: id, tickets: await ticketsFor(id) });
}

/** Crée le ticket / l'incident (Jira, ServiceNow, XSOAR) ou envoie l'événement au SIEM pour cette CVE. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const caller = await authorize(req);
  if (!caller) return unauthorized();
  const id = (await ctx.params).id.toUpperCase();
  if (!CVE_ID_RE.test(id)) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });

  let connector: unknown;
  try {
    connector = ((await req.json()) as { connector?: unknown })?.connector;
  } catch {
    connector = undefined;
  }
  if (typeof connector !== "string" || !(CONNECTOR_IDS as string[]).includes(connector)) {
    return NextResponse.json({ error: `connector doit valoir ${CONNECTOR_IDS.join(", ")}` }, { status: 400 });
  }
  const info = connectorInfo(connector as ConnectorId);
  if (!info.configured) {
    return NextResponse.json({ error: `${info.name} n'est pas configuré. Variables manquantes : ${info.missing.join(", ")}.` }, { status: 409 });
  }

  const detail = await getCveDetail(id);
  if (!detail) return NextResponse.json({ error: `${id} introuvable dans NVD et CVE.org` }, { status: 404 });
  try {
    const t = await sendAndRecord(info.id, detail, detail.remediation, appUrl(), caller.userId);
    return NextResponse.json({ cve: id, ticket: t }, { status: 201 });
  } catch (e) {
    if (e instanceof AlreadySentError) {
      return NextResponse.json({ error: `Déjà envoyé à ${info.name}.`, ticket: e.existing }, { status: 409 });
    }
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[connecteurs] ${info.name} ${id} : ${msg}`);
    return NextResponse.json({ error: `Échec de l'envoi à ${info.name} : ${msg}` }, { status: 502 });
  }
}

import { NextResponse } from "next/server";
import { authorize, orgRequired, unauthorized } from "@/lib/apiauth";
import { CONNECTOR_IDS, connectorInfo, type ConnectorId } from "@/lib/connectors";
import { CVE_ID_RE, getCveDetail } from "@/lib/detail";
import { getOrgConnector } from "@/lib/orgconnectors";
import { AlreadySentError, appUrl, sendAndRecord, ticketsFor } from "@/lib/ticketstore";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const caller = await authorize(req);
  if (!caller) return unauthorized();
  const id = (await ctx.params).id.toUpperCase();
  if (!CVE_ID_RE.test(id)) return NextResponse.json({ error: "Identifiant CVE invalide" }, { status: 400 });
  // Tickets de l'organisation de l'appelant uniquement
  return NextResponse.json({ cve: id, tickets: caller.orgId ? await ticketsFor(id, caller.orgId) : [] });
}

/** Crée le ticket / l'incident (Jira, ServiceNow, XSOAR) ou envoie l'événement au SIEM pour cette CVE. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const caller = await authorize(req);
  if (!caller) return unauthorized();
  if (!caller.orgId) return orgRequired();
  if (!caller.canWrite) return NextResponse.json({ error: "Droits insuffisants : rôle analyste ou clé d’API en écriture requis." }, { status: 403 });
  const orgId = caller.orgId;
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
  const conn = await getOrgConnector(orgId, connector as ConnectorId);
  const info = connectorInfo(connector as ConnectorId, conn?.cfg ?? {});
  if (!conn || !conn.enabled || !info.configured) {
    return NextResponse.json({ error: `${info.name} n'est pas configuré pour votre organisation (Mon compte → Organisation → Intégrations).` }, { status: 409 });
  }

  const detail = await getCveDetail(id, { orgId });
  if (!detail) return NextResponse.json({ error: `${id} introuvable dans NVD et CVE.org` }, { status: 404 });
  try {
    const t = await sendAndRecord(orgId, info.id, conn.cfg, detail, detail.remediation, appUrl(), caller.userId);
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

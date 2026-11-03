import { NextResponse } from "next/server";
import { CONNECTOR_IDS, testConnector, type ConnectorId } from "@/lib/connectors";
import { pullMisp, pullTaxii } from "@/lib/cti/leakconnectors";
import { processQueue } from "@/lib/cti/leakstore";
import { getOrgConnector, markConnectorRun, ORG_CONNECTOR_TYPES, type OrgConnectorType } from "@/lib/orgconnectors";
import { requireTenant } from "@/lib/tenant";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Vérifie un connecteur de l'organisation (MISP, TAXII : collecte immédiate de ses événements privés). */
export async function POST(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  const id = ((await req.json().catch(() => ({}))) as { connector?: unknown }).connector;
  if (typeof id !== "string" || !ORG_CONNECTOR_TYPES.includes(id as OrgConnectorType)) return NextResponse.json({ error: "Connecteur inconnu." }, { status: 400 });
  const c = await getOrgConnector(t.orgId, id as OrgConnectorType);
  if (!c) return NextResponse.json({ ok: false, message: "Connecteur non configuré." }, { status: 404 });
  try {
    let message: string;
    if ((CONNECTOR_IDS as string[]).includes(id)) message = await testConnector(id as ConnectorId, c.cfg);
    else {
      const r = id === "misp" ? await pullMisp(c.cfg, t.orgId) : await pullTaxii(c.cfg, t.orgId);
      await processQueue(20);
      message = "events" in r ? `Connexion réussie : ${r.events} événement(s) reçu(s).` : r.skipped;
    }
    await markConnectorRun(t.orgId, id as OrgConnectorType, null);
    return NextResponse.json({ ok: true, message });
  } catch (e) {
    const m = e instanceof Error ? e.message : String(e);
    await markConnectorRun(t.orgId, id as OrgConnectorType, m);
    return NextResponse.json({ ok: false, message: m }, { status: 502 });
  }
}

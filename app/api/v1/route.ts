import { NextResponse } from "next/server";
import { authorize, unauthorized } from "@/lib/apiauth";
import { listConnectors } from "@/lib/connectors";

export const dynamic = "force-dynamic";

/** Index de l'API : points d'accès et connecteurs disponibles. */
export async function GET(req: Request) {
  const caller = await authorize(req);
  if (!caller) return unauthorized();
  return NextResponse.json({
    name: "VigilantIQ API",
    version: "1",
    caller: caller.kind === "token" ? `jeton ${caller.name}` : caller.name,
    endpoints: {
      "GET /api/v1/vulns": "Vulnérabilités du jour. Filtres : priority=urgente,haute | min_priority=haute | exploited=true | poc=true | stack=fortinet,nginx | q=texte | since=ISO8601 | limit=500",
      "GET /api/v1/vulns/{CVE}": "Fiche complète : versions, références, exploits/PoC, plan de remédiation, tickets",
      "GET /api/v1/vulns/{CVE}/tickets": "Tickets déjà créés pour la CVE",
      "POST /api/v1/vulns/{CVE}/tickets": 'Crée un ticket ou envoie l\'événement : {"connector":"jira|servicenow|xsoar|siem"}',
      "GET /api/v1/exploits": "Codes d'exploitation / PoC détectés. Filtres : days=7 | cve=CVE-…",
    },
    connectors: listConnectors().map(({ id, name, configured, auto }) => ({ id, name, configured, auto })),
  });
}

/**
 * Connecteurs vers les outils de l'équipe : Jira, ServiceNow, Cortex XSOAR (tickets / incidents)
 * et SIEM (événements : Splunk HEC, Elasticsearch, ou webhook JSON pour Sentinel, QRadar, etc.).
 *
 * Configuration unique par l'administrateur, dans les variables d'environnement (voir README).
 * Ce module ne touche pas à la base : il construit le contenu et l'envoie. Le dédoublonnage est dans ticketstore.ts.
 */
import type { Priority, Remediation, Vuln } from "./types.ts";

export type ConnectorId = "jira" | "servicenow" | "xsoar" | "siem";
export const CONNECTOR_IDS: ConnectorId[] = ["jira", "servicenow", "xsoar", "siem"];

export interface ConnectorInfo {
  id: ConnectorId;
  name: string;
  /** ticket = crée un ticket / incident ; event = envoie un événement au SIEM */
  kind: "ticket" | "event";
  configured: boolean;
  /** Variables manquantes (noms seulement, jamais les valeurs) */
  missing: string[];
  /** Envoi automatique quotidien des CVE prioritaires */
  auto: boolean;
}

export interface SendResult {
  externalId: string;
  url: string;
}

const env = (k: string) => (process.env[k] ?? "").trim();
const trimSlash = (u: string) => u.replace(/\/+$/, "");

const REQUIRED: Record<ConnectorId, string[]> = {
  jira: ["JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"],
  servicenow: ["SERVICENOW_URL", "SERVICENOW_USER", "SERVICENOW_PASSWORD"],
  xsoar: ["XSOAR_URL", "XSOAR_API_KEY"],
  siem: ["SIEM_URL"],
};

const NAMES: Record<ConnectorId, string> = { jira: "Jira", servicenow: "ServiceNow", xsoar: "Cortex XSOAR", siem: "SIEM" };

export function autoConnectors(): ConnectorId[] {
  const raw = process.env.CONNECTORS_AUTO ?? "siem";
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s): s is ConnectorId => (CONNECTOR_IDS as string[]).includes(s));
}

export function connectorInfo(id: ConnectorId): ConnectorInfo {
  const missing = REQUIRED[id].filter((k) => !env(k));
  return { id, name: NAMES[id], kind: id === "siem" ? "event" : "ticket", configured: missing.length === 0, missing, auto: autoConnectors().includes(id) };
}

export function listConnectors(): ConnectorInfo[] {
  return CONNECTOR_IDS.map(connectorInfo);
}

/** Priorité minimale pour l'envoi automatique (urgente par défaut). */
export function autoMinPriority(): Priority {
  const p = (process.env.CONNECTORS_MIN_PRIORITY ?? "urgente").trim().toLowerCase();
  return (["urgente", "haute", "moyenne", "basse"] as const).includes(p as Priority) ? (p as Priority) : "urgente";
}

// ---------- Contenu ----------

const PRIO: Record<Priority, string> = { urgente: "Urgente", haute: "Haute", moyenne: "Moyenne", basse: "Basse" };

export interface TicketContent {
  title: string;
  summary: string;
  facts: [string, string][];
  steps: string[];
  links: [string, string][];
}

function productOf(v: Vuln): string {
  const a = v.affected[0];
  if (a) return a.product;
  return v.products[0]?.replace(/_/g, " ") ?? v.kev?.name ?? "Produit non précisé";
}

/** Contenu commun à tous les outils, en français. */
export function ticketContent(v: Vuln, r: Remediation, appUrl: string): TicketContent {
  const pocs = v.exploits?.length ?? 0;
  const facts: [string, string][] = [
    ["Priorité", `${PRIO[v.priority]} (score ${v.score}/100)`],
    ["CVSS", v.cvss != null ? `${v.cvss.toFixed(1)}${v.cvssVersion ? ` (v${v.cvssVersion})` : ""}` : "non publié"],
    ["EPSS", v.epss != null ? `${(v.epss * 100).toFixed(1)} %` : "non disponible"],
    ["Exploitée activement", v.kev ? `Oui (CISA KEV${v.kev.ransomware ? ", rançongiciels" : ""})` : v.ssvc?.exploitation === "active" ? "Oui (SSVC)" : "Non signalé"],
    ["Codes d'exploitation publics", pocs ? String(pocs) : "Aucun repéré"],
    ["Délai recommandé", r.deadline],
  ];
  // Un même produit peut venir de plusieurs sources (éditeur, NVD, OSV) : on garde la première, la plus fiable.
  const seen = new Set<string>();
  const products = v.affected.filter((a) => (seen.has(a.product.toLowerCase()) ? false : (seen.add(a.product.toLowerCase()), true)));
  const impacted = products.slice(0, 4).map((a) => `${a.product} : ${a.ranges.slice(0, 4).join(", ") || "toutes versions"}`);
  if (impacted.length) facts.push(["Versions impactées", impacted.join(" ; ")]);
  const fixed = products.filter((a) => a.fixed.length).slice(0, 4).map((a) => `${a.product} : ${a.fixed.slice(0, 4).join(", ")}`);
  if (fixed.length) facts.push(["Versions corrigées", fixed.join(" ; ")]);

  const steps = r.steps.slice(0, 8).map((s) => {
    const extra = s.originalFr ?? s.original;
    return `${s.text}${extra ? ` — ${extra.slice(0, 400)}` : ""}${s.url ? ` (${s.url})` : ""}`;
  });

  const links: [string, string][] = [[`Fiche VigilantIQ`, `${trimSlash(appUrl)}/cve/${v.id}`], ["NVD", `https://nvd.nist.gov/vuln/detail/${v.id}`]];
  for (const ref of v.references.filter((x) => x.tags.includes("Avis éditeur") || x.tags.includes("Correctif")).slice(0, 2)) links.push(["Avis éditeur", ref.url]);
  for (const e of (v.exploits ?? []).slice(0, 3)) links.push([`PoC : ${e.title}`, e.url]);

  return {
    title: `[VigilantIQ] ${v.id} – ${productOf(v)} – priorité ${PRIO[v.priority].toLowerCase()}`,
    summary: v.ai?.resume || v.description.slice(0, 600),
    facts,
    steps,
    links,
  };
}

/** Version texte (ServiceNow, XSOAR). */
export function ticketText(c: TicketContent): string {
  return [
    c.summary,
    "",
    ...c.facts.map(([k, val]) => `${k} : ${val}`),
    "",
    "Remédiation :",
    ...c.steps.map((s, i) => `${i + 1}. ${s}`),
    "",
    "Liens :",
    ...c.links.map(([k, u]) => `- ${k} : ${u}`),
  ].join("\n");
}

/** Description au format Atlassian Document Format (Jira Cloud, API v3). */
export function jiraDoc(c: TicketContent): unknown {
  const p = (text: string) => ({ type: "paragraph", content: [{ type: "text", text }] });
  const heading = (text: string) => ({ type: "heading", attrs: { level: 3 }, content: [{ type: "text", text }] });
  const bullets = (items: unknown[][]) => ({
    type: "bulletList",
    content: items.map((content) => ({ type: "listItem", content: [{ type: "paragraph", content }] })),
  });
  return {
    type: "doc",
    version: 1,
    content: [
      p(c.summary),
      bullets(c.facts.map(([k, val]) => [{ type: "text", text: `${k} : `, marks: [{ type: "strong" }] }, { type: "text", text: val }])),
      heading("Remédiation"),
      { type: "orderedList", content: c.steps.map((s) => ({ type: "listItem", content: [p(s)] })) },
      heading("Liens"),
      bullets(c.links.map(([k, u]) => [{ type: "text", text: k, marks: [{ type: "link", attrs: { href: u } }] }])),
    ],
  };
}

/** Événement SIEM : champs stables, en anglais, faciles à indexer. */
export function siemEvent(v: Vuln, r: Remediation, appUrl: string, type: "vulnerability" | "test" = "vulnerability") {
  return {
    source: "vigilantiq",
    type,
    cve: v.id,
    title: `${v.id} – ${productOf(v)}`,
    priority: v.priority,
    score: v.score,
    cvss: v.cvss,
    cvss_vector: v.vector,
    epss: v.epss,
    exploited: Boolean(v.kev) || v.ssvc?.exploitation === "active",
    kev_due_date: v.kev?.dueDate ?? null,
    ransomware: v.kev?.ransomware ?? false,
    poc_count: v.exploits?.length ?? 0,
    vendors: v.vendors,
    products: v.products,
    affected: v.affected.map((a) => ({ vendor: a.vendor, product: a.product, ranges: a.ranges, fixed: a.fixed })),
    patch_available: r.patchAvailable,
    remediation_deadline: r.deadlineDate,
    summary: v.ai?.resume || v.description.slice(0, 500),
    published: v.published,
    url: `${trimSlash(appUrl)}/cve/${v.id}`,
    timestamp: new Date().toISOString(),
  };
}

// ---------- Envoi ----------

async function check(res: Response, what: string): Promise<any> {
  const text = await res.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!res.ok) {
    const detail =
      body?.errorMessages?.join(" ") ||
      (body?.errors && typeof body.errors === "object" ? Object.values(body.errors).join(" ") : "") ||
      body?.error?.message ||
      body?.error ||
      body?.text ||
      text.slice(0, 200);
    throw new Error(`${what} a répondu ${res.status}${detail ? ` : ${String(detail).slice(0, 300)}` : ""}`);
  }
  return body;
}

const TIMEOUT = 20_000;

async function sendJira(c: TicketContent, v: Vuln): Promise<SendResult> {
  const base = trimSlash(env("JIRA_URL"));
  const auth = Buffer.from(`${env("JIRA_EMAIL")}:${env("JIRA_API_TOKEN")}`).toString("base64");
  const labels = (process.env.JIRA_LABELS ?? "vigilantiq,cve")
    .split(",")
    .map((s) => s.trim().replace(/\s+/g, "-"))
    .filter(Boolean);
  const res = await fetch(`${base}/rest/api/3/issue`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      fields: {
        project: { key: env("JIRA_PROJECT_KEY") },
        issuetype: { name: env("JIRA_ISSUE_TYPE") || "Task" },
        summary: c.title.slice(0, 250),
        description: jiraDoc(c),
        labels: [...labels, v.id.toLowerCase(), `priorite-${v.priority}`],
      },
    }),
    signal: AbortSignal.timeout(TIMEOUT),
    cache: "no-store",
  });
  const body = await check(res, "Jira");
  return { externalId: String(body?.key ?? body?.id ?? ""), url: body?.key ? `${base}/browse/${body.key}` : "" };
}

const SN_LEVEL: Record<Priority, string> = { urgente: "1", haute: "2", moyenne: "2", basse: "3" };

async function sendServiceNow(c: TicketContent, v: Vuln): Promise<SendResult> {
  const base = trimSlash(env("SERVICENOW_URL"));
  const table = env("SERVICENOW_TABLE") || "incident";
  const auth = Buffer.from(`${env("SERVICENOW_USER")}:${env("SERVICENOW_PASSWORD")}`).toString("base64");
  const record: Record<string, string> = {
    short_description: c.title.slice(0, 160),
    description: ticketText(c),
    impact: SN_LEVEL[v.priority],
    urgency: SN_LEVEL[v.priority],
    correlation_id: `vigilantiq:${v.id}`,
    correlation_display: "VigilantIQ",
  };
  if (env("SERVICENOW_ASSIGNMENT_GROUP")) record.assignment_group = env("SERVICENOW_ASSIGNMENT_GROUP");
  if (env("SERVICENOW_CALLER")) record.caller_id = env("SERVICENOW_CALLER");
  const res = await fetch(`${base}/api/now/table/${encodeURIComponent(table)}`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(record),
    signal: AbortSignal.timeout(TIMEOUT),
    cache: "no-store",
  });
  const body = await check(res, "ServiceNow");
  const r = body?.result ?? {};
  return {
    externalId: String(r.number ?? r.sys_id ?? ""),
    url: r.sys_id ? `${base}/nav_to.do?uri=${encodeURIComponent(`${table}.do?sys_id=${r.sys_id}`)}` : "",
  };
}

const XSOAR_SEVERITY: Record<Priority, number> = { urgente: 4, haute: 3, moyenne: 2, basse: 1 };

function xsoarHeaders(): Record<string, string> {
  const h: Record<string, string> = { Authorization: env("XSOAR_API_KEY"), "Content-Type": "application/json", Accept: "application/json" };
  // XSOAR 8 (cloud) exige l'identifiant de la clé ; XSOAR 6 ne l'utilise pas.
  if (env("XSOAR_API_KEY_ID")) h["x-xdr-auth-id"] = env("XSOAR_API_KEY_ID");
  return h;
}

async function sendXsoar(c: TicketContent, v: Vuln): Promise<SendResult> {
  const base = trimSlash(env("XSOAR_URL"));
  const res = await fetch(`${base}/incident`, {
    method: "POST",
    headers: xsoarHeaders(),
    body: JSON.stringify({
      name: c.title.slice(0, 250),
      type: env("XSOAR_INCIDENT_TYPE") || "Vulnerability",
      severity: XSOAR_SEVERITY[v.priority],
      details: ticketText(c),
      labels: [
        { type: "CVE", value: v.id },
        { type: "Source", value: "VigilantIQ" },
        { type: "Priority", value: v.priority },
      ],
      createInvestigation: true,
    }),
    signal: AbortSignal.timeout(TIMEOUT),
    cache: "no-store",
  });
  const body = await check(res, "XSOAR");
  const id = String(body?.id ?? body?.incident_id ?? "");
  const tpl = env("XSOAR_INCIDENT_URL");
  return { externalId: id, url: tpl && id ? tpl.replace("{id}", id) : "" };
}

/** Envoie un ou plusieurs événements au SIEM, au format choisi par SIEM_FORMAT. */
export async function sendSiemEvents(events: Record<string, unknown>[]): Promise<void> {
  const url = env("SIEM_URL");
  const format = (env("SIEM_FORMAT") || "json").toLowerCase();
  const token = env("SIEM_TOKEN");
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  let body: string;
  if (format === "splunk") {
    if (token) headers.Authorization = `Splunk ${token}`;
    // Splunk HEC accepte plusieurs événements concaténés dans une même requête.
    body = events
      .map((e) =>
        JSON.stringify({
          time: Math.floor(Date.now() / 1000),
          source: "vigilantiq",
          sourcetype: env("SIEM_SOURCETYPE") || "vigilantiq:cve",
          ...(env("SIEM_INDEX") ? { index: env("SIEM_INDEX") } : {}),
          event: e,
        }),
      )
      .join("\n");
  } else if (format === "elastic") {
    if (token) headers.Authorization = `ApiKey ${token}`;
    headers["Content-Type"] = "application/x-ndjson";
    // API _bulk : SIEM_URL = https://hôte:9200/<index>/_bulk
    body = events.map((e) => `${JSON.stringify({ index: {} })}\n${JSON.stringify({ "@timestamp": e.timestamp, ...e })}`).join("\n") + "\n";
  } else {
    if (token) headers.Authorization = `Bearer ${token}`;
    // Webhook générique : tableau JSON (Sentinel via Logic App ou DCR, QRadar, Graylog, n8n…)
    body = JSON.stringify(events);
  }
  const res = await fetch(url, { method: "POST", headers, body, signal: AbortSignal.timeout(TIMEOUT), cache: "no-store" });
  const json = await check(res, "SIEM");
  if (format === "elastic" && json?.errors) throw new Error("SIEM (Elasticsearch) : certains événements ont été refusés");
}

/** Crée le ticket / l'incident, ou envoie l'événement, pour une CVE. */
export async function sendToConnector(id: ConnectorId, v: Vuln, r: Remediation, appUrl: string): Promise<SendResult> {
  const info = connectorInfo(id);
  if (!info.configured) throw new Error(`${info.name} n'est pas configuré (manque : ${info.missing.join(", ")})`);
  const c = ticketContent(v, r, appUrl);
  if (id === "jira") return sendJira(c, v);
  if (id === "servicenow") return sendServiceNow(c, v);
  if (id === "xsoar") return sendXsoar(c, v);
  await sendSiemEvents([siemEvent(v, r, appUrl)]);
  return { externalId: "", url: "" };
}

/** Vérifie les identifiants sans rien créer (sauf pour le SIEM : un événement de type « test »). */
export async function testConnector(id: ConnectorId): Promise<string> {
  const info = connectorInfo(id);
  if (!info.configured) throw new Error(`${info.name} n'est pas configuré (manque : ${info.missing.join(", ")})`);
  if (id === "jira") {
    const base = trimSlash(env("JIRA_URL"));
    const auth = Buffer.from(`${env("JIRA_EMAIL")}:${env("JIRA_API_TOKEN")}`).toString("base64");
    const res = await fetch(`${base}/rest/api/3/project/${encodeURIComponent(env("JIRA_PROJECT_KEY"))}`, {
      headers: { Authorization: `Basic ${auth}`, Accept: "application/json" },
      signal: AbortSignal.timeout(TIMEOUT),
      cache: "no-store",
    });
    const p = await check(res, "Jira");
    return `Connexion réussie au projet ${p?.name ?? env("JIRA_PROJECT_KEY")}.`;
  }
  if (id === "servicenow") {
    const base = trimSlash(env("SERVICENOW_URL"));
    const table = env("SERVICENOW_TABLE") || "incident";
    const auth = Buffer.from(`${env("SERVICENOW_USER")}:${env("SERVICENOW_PASSWORD")}`).toString("base64");
    const res = await fetch(`${base}/api/now/table/${encodeURIComponent(table)}?sysparm_limit=1&sysparm_fields=sys_id`, {
      headers: { Authorization: `Basic ${auth}`, Accept: "application/json" },
      signal: AbortSignal.timeout(TIMEOUT),
      cache: "no-store",
    });
    await check(res, "ServiceNow");
    return `Connexion réussie à la table ${table}.`;
  }
  if (id === "xsoar") {
    const res = await fetch(`${trimSlash(env("XSOAR_URL"))}/incidents/search`, {
      method: "POST",
      headers: xsoarHeaders(),
      body: JSON.stringify({ filter: { page: 0, size: 1 } }),
      signal: AbortSignal.timeout(TIMEOUT),
      cache: "no-store",
    });
    await check(res, "XSOAR");
    return "Connexion réussie à Cortex XSOAR.";
  }
  await sendSiemEvents([{ source: "vigilantiq", type: "test", message: "Test de connexion VigilantIQ", timestamp: new Date().toISOString() }]);
  return "Événement de test envoyé au SIEM.";
}

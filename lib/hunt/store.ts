/**
 * Threat Hunting — base de données : équipements et clés d'agent, réception des données de l'agent,
 * connecteur SIEM/EDR, chasse (correspondance avec tous les IOC), détections, fuites et purge.
 */
import { createHash, randomBytes } from "node:crypto";
import { and, desc, eq, gt, inArray, isNotNull, lt, ne, sql } from "drizzle-orm";
import { dbConfigured, getDb } from "@/db";
import { huntAsset, huntFinding, huntObservation, huntRun, huntSiem, leakEvent, leakMatch, leakSource, watchAccount, watchItem } from "@/db/schema";
import { verifySignature } from "../cti/leaks.ts";
import { serverSecret } from "../cti/leakstore.ts";
import { publicHttpsUrl } from "../netguard.ts";
import { getIocs } from "../cti/store.ts";
import { agentKey, agentKeyMatches, buildIndex, extractEvent, hunt, newSalt, parseAgentKey, parseAgentPayload, seal, unseal, type FindingDraft, type IocIndex, type Obs } from "./core.ts";

export class HuntError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

const OBS_RETENTION_DAYS = () => Number(process.env.HUNT_RETENTION_DAYS || 30);
const MAX_ASSETS = () => Number(process.env.HUNT_MAX_ASSETS || 200);
const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

// ---------- Index des IOC (toutes les sources de l'application) ----------

async function buildIocIndex(): Promise<{ idx: IocIndex; sources: { name: string; ok: boolean; count: number }[]; generatedAt: string }> {
  const feed = await getIocs();
  return { idx: buildIndex(feed.items), sources: feed.sources, generatedAt: feed.generatedAt };
}
// Les Map ne se mettent pas en cache : on garde le flux en cache et on reconstruit l'index par instance.
const g = globalThis as unknown as { __huntIdx?: { at: number; v: Awaited<ReturnType<typeof buildIocIndex>> } };
export async function iocIndex() {
  if (g.__huntIdx && Date.now() - g.__huntIdx.at < 10 * 60_000) return g.__huntIdx.v;
  const v = await buildIocIndex();
  g.__huntIdx = { at: Date.now(), v };
  return v;
}

async function ownDomains(orgId: string): Promise<string[]> {
  const rows = await getDb()
    .select({ v: watchItem.value })
    .from(watchItem)
    .where(and(eq(watchItem.orgId, orgId), eq(watchItem.kind, "domain"), isNotNull(watchItem.verifiedAt)));
  return rows.map((r) => r.v);
}

// ---------- Équipements ----------

export const ASSET_KINDS = ["poste", "serveur", "reseau", "cloud", "autre"] as const;

export interface AssetRow {
  id: number;
  name: string;
  kind: string;
  source: string;
  hostname: string | null;
  os: string;
  lastIp: string | null;
  lastSeenAt: string | null;
  createdAt: string;
  hasKey: boolean;
  observations: number;
  open: number;
  worst: string | null;
}

const SEV_RANK: Record<string, number> = { critique: 3, haute: 2, moyenne: 1, info: 0 };

export async function listAssets(orgId: string): Promise<AssetRow[]> {
  const db = getDb();
  const rows = await db.select().from(huntAsset).where(eq(huntAsset.orgId, orgId)).orderBy(huntAsset.name);
  const obs = await db.select({ a: huntObservation.assetId, n: sql<number>`count(*)::int` }).from(huntObservation).where(eq(huntObservation.orgId, orgId)).groupBy(huntObservation.assetId);
  const fin = await db
    .select({ a: huntFinding.assetId, s: huntFinding.severity, n: sql<number>`count(*)::int` })
    .from(huntFinding)
    .where(and(eq(huntFinding.orgId, orgId), inArray(huntFinding.status, ["nouveau", "en_cours"])))
    .groupBy(huntFinding.assetId, huntFinding.severity);
  const obsBy = new Map(obs.map((o) => [o.a, o.n]));
  return rows.map((r) => {
    const f = fin.filter((x) => x.a === r.id);
    const worst = f.sort((a, b) => SEV_RANK[b.s] - SEV_RANK[a.s])[0]?.s ?? null;
    return {
      id: r.id,
      name: r.name,
      kind: r.kind,
      source: r.source,
      hostname: r.hostname,
      os: r.os,
      lastIp: r.lastIp,
      lastSeenAt: r.lastSeenAt?.toISOString() ?? null,
      createdAt: r.createdAt.toISOString(),
      hasKey: Boolean(r.keySalt),
      observations: obsBy.get(r.id) ?? 0,
      open: f.reduce((s, x) => s + x.n, 0),
      worst,
    };
  });
}

/** Nouvel équipement surveillé par l'agent : la clé n'est renvoyée qu'une fois. */
export async function createAsset(orgId: string, f: { name?: unknown; kind?: unknown }): Promise<{ id: number; key: string }> {
  const name = typeof f.name === "string" ? f.name.trim().slice(0, 80) : "";
  if (!name) throw new HuntError("Nom de l’équipement obligatoire.");
  const kind = ASSET_KINDS.includes(f.kind as (typeof ASSET_KINDS)[number]) ? (f.kind as string) : "poste";
  const db = getDb();
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(huntAsset).where(eq(huntAsset.orgId, orgId));
  if (n >= MAX_ASSETS()) throw new HuntError(`Limite de ${MAX_ASSETS()} équipements atteinte.`);
  const salt = newSalt();
  const [row] = await db.insert(huntAsset).values({ orgId, name, kind, source: "agent", keySalt: salt }).onConflictDoNothing().returning({ id: huntAsset.id });
  if (!row) throw new HuntError("Un équipement porte déjà ce nom.");
  return { id: row.id, key: agentKey(serverSecret(), row.id, salt) };
}

export async function rotateAssetKey(orgId: string, id: number): Promise<string> {
  const salt = newSalt();
  const res = await getDb()
    .update(huntAsset)
    .set({ keySalt: salt, source: "agent" })
    .where(and(eq(huntAsset.orgId, orgId), eq(huntAsset.id, id)))
    .returning({ id: huntAsset.id });
  if (!res.length) throw new HuntError("Équipement introuvable.", 404);
  return agentKey(serverSecret(), id, salt);
}

export async function deleteAsset(orgId: string, id: number): Promise<void> {
  await getDb().delete(huntAsset).where(and(eq(huntAsset.orgId, orgId), eq(huntAsset.id, id)));
}

// ---------- Observables et détections ----------

async function saveObservations(orgId: string, assetId: number, obs: Obs[]): Promise<void> {
  const db = getDb();
  const now = new Date();
  for (let i = 0; i < obs.length; i += 500) {
    await db
      .insert(huntObservation)
      .values(obs.slice(i, i + 500).map((o) => ({ orgId, assetId, kind: o.kind, value: o.value.slice(0, 800), context: o.context })))
      .onConflictDoUpdate({
        target: [huntObservation.assetId, huntObservation.kind, huntObservation.value],
        set: { lastSeen: now, count: sql`${huntObservation.count} + 1`, context: sql`excluded.context` },
      });
  }
}

/** Enregistre les détections ; une détection résolue qui réapparaît redevient « nouveau ». */
async function saveFindings(orgId: string, assetId: number | null, drafts: FindingDraft[]): Promise<number> {
  if (!drafts.length) return 0;
  const db = getDb();
  const now = new Date();
  let created = 0;
  for (const d of drafts) {
    const [r] = await db
      .insert(huntFinding)
      .values({ orgId, assetId, ...d, indicator: d.indicator.slice(0, 800), firstSeen: now, lastSeen: now })
      .onConflictDoUpdate({
        target: [huntFinding.orgId, huntFinding.assetId, huntFinding.kind, huntFinding.indicator],
        set: {
          lastSeen: now,
          updatedAt: now,
          evidence: sql`excluded.evidence`,
          severity: sql`excluded.severity`,
          threat: sql`excluded.threat`,
          status: sql`case when ${huntFinding.status} = 'resolu' then 'nouveau' else ${huntFinding.status} end`,
        },
      })
      .returning({ id: huntFinding.id, created: sql<boolean>`(xmax = 0)` });
    if (r?.created) created++;
  }
  return created;
}

async function ingest(orgId: string, assetId: number, obs: Obs[]): Promise<{ observations: number; findings: number }> {
  await saveObservations(orgId, assetId, obs);
  const { idx } = await iocIndex();
  const drafts = hunt(obs, idx, { ownDomains: await ownDomains(orgId) });
  return { observations: obs.length, findings: await saveFindings(orgId, assetId, drafts) };
}

// ---------- Agent collecteur ----------

/** Authentifie l'agent : clé de l'équipement (Bearer), signature HMAC du corps, fenêtre de 5 minutes, débit. */
export async function authenticateAgent(headers: Headers, body: string) {
  const auth = headers.get("authorization") ?? "";
  const key = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const p = parseAgentKey(key);
  if (!p) throw new HuntError("Clé d’agent absente ou mal formée.", 401);
  const [asset] = await getDb().select().from(huntAsset).where(eq(huntAsset.id, p.id));
  if (!asset || !agentKeyMatches(serverSecret(), key, asset.keySalt)) throw new HuntError("Clé d’agent invalide ou révoquée.", 401);
  const bad = verifySignature(key, headers.get("x-vq-timestamp"), body, headers.get("x-vq-signature"));
  if (bad) throw new HuntError(bad, 401);
  if (asset.lastSeenAt && Date.now() - asset.lastSeenAt.getTime() < 60_000) throw new HuntError("Un envoi par minute au plus par équipement.", 429);
  return asset;
}

export async function ingestAgent(asset: typeof huntAsset.$inferSelect, text: string) {
  const { host, obs, counts } = parseAgentPayload(text);
  await getDb()
    .update(huntAsset)
    .set({ lastSeenAt: new Date(), ...(host.name ? { hostname: host.name } : {}), ...(host.os ? { os: host.os } : {}), ...(host.ip ? { lastIp: host.ip } : {}) })
    .where(eq(huntAsset.id, asset.id));
  const r = await ingest(asset.orgId, asset.id, obs);
  return { ...r, counts };
}

// ---------- Connecteur SIEM/EDR ----------

export type SiemType = "elastic" | "splunk" | "cortex";
export interface SiemAuth {
  /** cortex_standard / cortex_advanced : clés d'API Cortex XDR (identifiant + clé) */
  kind: "basic" | "apikey" | "bearer" | "cortex_standard" | "cortex_advanced";
  user?: string;
  password?: string;
  token?: string;
  keyId?: string;
}
export interface SiemView {
  type: SiemType;
  url: string;
  index: string;
  authKind: string;
  enabled: boolean;
  lastPullAt: string | null;
  lastError: string | null;
  lastStats: Record<string, unknown> | null;
}

/** Adresse d'un SIEM : HTTPS, nom public (pas d'adresse locale ou privée). */
export function checkSiemUrl(raw: string): string {
  try {
    return publicHttpsUrl(raw, "Le SIEM").replace(/\?.*$/, "");
  } catch (e) {
    throw new HuntError(e instanceof Error ? e.message : "Adresse du SIEM invalide.");
  }
}

export async function getSiem(orgId: string): Promise<SiemView | null> {
  const [r] = await getDb().select().from(huntSiem).where(eq(huntSiem.orgId, orgId));
  if (!r) return null;
  let authKind = "?";
  try {
    authKind = (JSON.parse(unseal(serverSecret(), r.authEnc)) as SiemAuth).kind;
  } catch {
    /* clé serveur changée : identifiants à ressaisir */
  }
  return { type: r.type as SiemType, url: r.url, index: r.index, authKind, enabled: r.enabled, lastPullAt: r.lastPullAt?.toISOString() ?? null, lastError: r.lastError, lastStats: r.lastStats ?? null };
}

export async function saveSiem(orgId: string, f: Record<string, unknown>): Promise<void> {
  const type = f.type === "splunk" ? "splunk" : f.type === "elastic" ? "elastic" : f.type === "cortex" ? "cortex" : null;
  if (!type) throw new HuntError("Type de SIEM inconnu.");
  let url = checkSiemUrl(String(f.url ?? ""));
  if (type === "cortex") url = cortexBase(url);
  const index = type === "cortex" ? "" : typeof f.index === "string" ? f.index.trim().slice(0, 200) : "";
  const a = (f.auth ?? {}) as Record<string, unknown>;
  const allowed = type === "cortex" ? ["cortex_standard", "cortex_advanced"] : ["basic", "apikey", "bearer"];
  const kind = allowed.includes(String(a.kind)) ? (a.kind as SiemAuth["kind"]) : null;
  if (!kind) throw new HuntError("Mode d’authentification inconnu.");
  const auth: SiemAuth =
    kind === "basic"
      ? { kind, user: String(a.user ?? ""), password: String(a.password ?? "") }
      : kind.startsWith("cortex")
        ? { kind, keyId: String(a.keyId ?? "").trim(), token: String(a.token ?? "").trim() }
        : { kind, token: String(a.token ?? "") };
  if ((kind === "basic" && (!auth.user || !auth.password)) || (kind !== "basic" && !auth.token)) throw new HuntError("Identifiants incomplets.");
  if (kind.startsWith("cortex") && !/^\d{1,10}$/.test(auth.keyId ?? "")) throw new HuntError("Identifiant de clé Cortex XDR invalide (nombre affiché dans la colonne « ID » de la clé).");
  const authEnc = seal(serverSecret(), JSON.stringify(auth));
  await getDb()
    .insert(huntSiem)
    .values({ orgId, type, url, index, authEnc, enabled: true })
    .onConflictDoUpdate({ target: huntSiem.orgId, set: { type, url, index, authEnc, enabled: true, lastError: null, updatedAt: new Date() } });
}

export async function deleteSiem(orgId: string): Promise<void> {
  await getDb().delete(huntSiem).where(eq(huntSiem.orgId, orgId));
}

/**
 * Adresse de l'API Cortex XDR : « https://api-<tenant>.xdr.<région>.paloaltonetworks.com ».
 * L'adresse de la console (sans « api- ») est acceptée et convertie ; tout autre domaine est refusé.
 */
export function cortexBase(raw: string): string {
  const u = new URL(raw);
  let host = u.hostname.toLowerCase();
  if (!/\.paloaltonetworks\.com$/.test(host)) throw new HuntError("Adresse Cortex XDR attendue : https://api-<locataire>.xdr.<région>.paloaltonetworks.com");
  if (!host.startsWith("api-")) host = `api-${host}`;
  return `https://${host}`;
}

/** En-têtes Cortex XDR : clé standard (clé en clair) ou avancée (SHA-256 de clé + nonce + horodatage). */
function cortexHeaders(a: SiemAuth): Record<string, string> {
  const h: Record<string, string> = { "x-xdr-auth-id": a.keyId ?? "", "Content-Type": "application/json", Accept: "application/json" };
  if (a.kind === "cortex_advanced") {
    const nonce = randomBytes(48).toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(0, 64).padEnd(64, "0");
    const timestamp = String(Math.floor(Date.now() / 1000) * 1000);
    h["x-xdr-nonce"] = nonce;
    h["x-xdr-timestamp"] = timestamp;
    h.Authorization = createHash("sha256").update(`${a.token}${nonce}${timestamp}`, "utf8").digest("hex");
  } else h.Authorization = a.token ?? "";
  return h;
}

/**
 * Alertes Cortex XDR (avec leurs événements) reçues depuis `since`, à plat : une ligne par événement,
 * avec le nom d'hôte de l'alerte. Pagination par 100 (maximum de l'API), 10 requêtes/s au plus.
 */
async function fetchCortexEvents(url: string, auth: SiemAuth, since: Date, max: number): Promise<Record<string, unknown>[]> {
  const out: Record<string, unknown>[] = [];
  for (let from = 0; from < max; from += 100) {
    const res = await fetch(`${url}/public_api/v1/alerts/get_alerts_multi_events/`, {
      method: "POST",
      headers: cortexHeaders(auth),
      body: JSON.stringify({
        request_data: {
          filters: [{ field: "server_creation_time", operator: "gte", value: since.getTime() }],
          search_from: from,
          search_to: from + 100,
          sort: { field: "creation_time", keyword: "desc" },
        },
      }),
      signal: AbortSignal.timeout(45_000),
      cache: "no-store",
      redirect: "error",
    });
    if (!res.ok) {
      const why = res.status === 401 ? " (clé refusée : vérifiez l’identifiant, la clé et son type standard/avancé)" : res.status === 402 ? " (licence ou rôle de la clé insuffisant)" : res.status === 429 ? " (trop de requêtes)" : "";
      throw new Error(`Cortex XDR a répondu ${res.status}${why}`);
    }
    const j = (await res.json()) as { reply?: { alerts?: Record<string, unknown>[]; total_count?: number } };
    const alerts = j.reply?.alerts ?? [];
    for (const al of alerts) {
      const events = Array.isArray(al.events) ? (al.events as Record<string, unknown>[]) : [];
      const { events: _e, ...head } = al;
      out.push(head);
      for (const ev of events) out.push({ host_name: head.host_name, host_ip: head.host_ip, ...ev });
    }
    if (alerts.length < 100 || out.length >= max) break;
    await new Promise((r) => setTimeout(r, 150));
  }
  return out.slice(0, max);
}

function authHeader(a: SiemAuth): string {
  if (a.kind === "basic") return `Basic ${Buffer.from(`${a.user}:${a.password}`).toString("base64")}`;
  if (a.kind === "apikey") return `ApiKey ${a.token}`;
  return `Bearer ${a.token}`;
}

/** Récupère les événements récents du SIEM (24 h au plus, depuis la dernière collecte). */
export async function fetchSiemEvents(type: SiemType, url: string, index: string, auth: SiemAuth, since: Date, max = 3000): Promise<Record<string, unknown>[]> {
  if (type === "cortex") return fetchCortexEvents(url, auth, since, max);
  const headers = { Authorization: authHeader(auth), Accept: "application/json" };
  if (type === "elastic") {
    const res = await fetch(`${url}/${encodeURIComponent(index || "*").replace(/%2A/g, "*").replace(/%2C/g, ",")}/_search`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ size: Math.min(max, 10000), sort: [{ "@timestamp": { order: "desc", unmapped_type: "date" } }], query: { range: { "@timestamp": { gte: since.toISOString() } } } }),
      signal: AbortSignal.timeout(45_000),
      cache: "no-store",
      redirect: "error",
    });
    if (!res.ok) throw new Error(`Le SIEM a répondu ${res.status}${res.status === 401 || res.status === 403 ? " (identifiants refusés)" : ""}`);
    const j = (await res.json()) as { hits?: { hits?: { _source?: Record<string, unknown> }[] } };
    return (j.hits?.hits ?? []).map((h) => h._source ?? {}).filter((x) => x && typeof x === "object");
  }
  const earliest = Math.floor(since.getTime() / 1000);
  const search = `search ${index ? `index=${index}` : "index=*"} earliest=${earliest} | head ${max}`;
  const res = await fetch(`${url}/services/search/jobs/export`, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ search, output_mode: "json" }),
    signal: AbortSignal.timeout(45_000),
    cache: "no-store",
    redirect: "error",
  });
  if (!res.ok) throw new Error(`Splunk a répondu ${res.status}${res.status === 401 ? " (identifiants refusés)" : ""}`);
  const text = await res.text();
  const out: Record<string, unknown>[] = [];
  for (const line of text.split("\n")) {
    try {
      const r = JSON.parse(line) as { result?: Record<string, unknown> };
      if (r.result) out.push(r.result);
    } catch {
      /* ligne vide ou message de progression */
    }
  }
  return out;
}

/** Collecte SIEM d'un utilisateur : regroupement par hôte (équipements créés au besoin), observables, chasse. */
export async function pullSiem(orgId: string): Promise<{ events: number; hosts: number; observations: number; findings: number }> {
  const db = getDb();
  const [cfg] = await db.select().from(huntSiem).where(eq(huntSiem.orgId, orgId));
  if (!cfg || !cfg.enabled) throw new HuntError("Aucun connecteur SIEM/EDR configuré.", 404);
  const since = new Date(Math.max(cfg.lastPullAt?.getTime() ?? 0, Date.now() - 24 * 3600_000) - 5 * 60_000);
  try {
    const auth = JSON.parse(unseal(serverSecret(), cfg.authEnc)) as SiemAuth;
    const events = await fetchSiemEvents(cfg.type as SiemType, cfg.url, cfg.index, auth, since);
    const byHost = new Map<string, Obs[]>();
    for (const ev of events) {
      const { host, obs } = extractEvent(ev);
      if (!obs.length) continue;
      const h = host || "Hôte inconnu (SIEM)";
      byHost.set(h, [...(byHost.get(h) ?? []), ...obs]);
    }
    let observations = 0;
    let findings = 0;
    for (const [name, obs] of [...byHost.entries()].slice(0, MAX_ASSETS())) {
      await db.insert(huntAsset).values({ orgId, name, kind: "poste", source: "siem", hostname: name }).onConflictDoNothing();
      const [asset] = await db.select().from(huntAsset).where(and(eq(huntAsset.orgId, orgId), eq(huntAsset.name, name)));
      await db.update(huntAsset).set({ lastSeenAt: new Date() }).where(eq(huntAsset.id, asset.id));
      // Dédoublonnage entre événements d'un même hôte
      const uniq = new Map(obs.map((o) => [`${o.kind}|${o.value}`, o]));
      const r = await ingest(orgId, asset.id, [...uniq.values()].slice(0, 8000));
      observations += r.observations;
      findings += r.findings;
    }
    const stats = { events: events.length, hosts: byHost.size, observations, findings };
    await db.update(huntSiem).set({ lastPullAt: new Date(), lastError: null, lastStats: stats }).where(eq(huntSiem.orgId, orgId));
    return stats;
  } catch (e) {
    await db.update(huntSiem).set({ lastError: msg(e).slice(0, 300) }).where(eq(huntSiem.orgId, orgId));
    throw e instanceof HuntError ? e : new HuntError(`Collecte SIEM impossible : ${msg(e)}`, 502);
  }
}

// ---------- Chasse rétroactive ----------

/** Rejoue tous les observables récents contre les IOC du moment (un IOC publié aujourd'hui révèle une connexion d'hier). */
export async function huntUser(orgId: string, trigger = "manuel"): Promise<{ observations: number; findings: number; iocs: number; runId: number }> {
  const db = getDb();
  const [run] = await db.insert(huntRun).values({ orgId, kind: "chasse", trigger }).returning({ id: huntRun.id });
  try {
    const { idx } = await iocIndex();
    const own = await ownDomains(orgId);
    const since = new Date(Date.now() - OBS_RETENTION_DAYS() * 86_400_000);
    const rows = await db
      .select()
      .from(huntObservation)
      .where(and(eq(huntObservation.orgId, orgId), gt(huntObservation.lastSeen, since)));
    const byAsset = new Map<number, Obs[]>();
    for (const r of rows) byAsset.set(r.assetId, [...(byAsset.get(r.assetId) ?? []), { kind: r.kind as Obs["kind"], value: r.value, context: r.context as Obs["context"] }]);
    let findings = 0;
    for (const [assetId, obs] of byAsset) findings += await saveFindings(orgId, assetId, hunt(obs, idx, { ownDomains: own }));
    const stats = { observations: rows.length, findings, iocs: idx.size, assets: byAsset.size };
    await db.update(huntRun).set({ stats, finishedAt: new Date() }).where(eq(huntRun.id, run.id));
    return { ...stats, runId: run.id };
  } catch (e) {
    await db.update(huntRun).set({ error: msg(e).slice(0, 500), finishedAt: new Date() }).where(eq(huntRun.id, run.id));
    throw e;
  }
}

/** Passe quotidienne : collecte SIEM de chaque utilisateur, chasse rétroactive, purge. */
export async function huntDaily(): Promise<Record<string, unknown>> {
  if (!dbConfigured()) return {};
  const db = getDb();
  const siems = await db.select({ u: huntSiem.orgId }).from(huntSiem).where(eq(huntSiem.enabled, true));
  let siemOk = 0;
  for (const s of siems) {
    try {
      await pullSiem(s.u);
      siemOk++;
    } catch (e) {
      console.error(`[chasse] SIEM ${s.u} : ${msg(e)}`);
    }
  }
  const users = await db.selectDistinct({ u: huntObservation.orgId }).from(huntObservation);
  let findings = 0;
  for (const u of users) {
    try {
      findings += (await huntUser(u.u, "quotidien")).findings;
    } catch (e) {
      console.error(`[chasse] ${u.u} : ${msg(e)}`);
    }
  }
  const purged = await db.delete(huntObservation).where(lt(huntObservation.lastSeen, new Date(Date.now() - OBS_RETENTION_DAYS() * 86_400_000))).returning({ id: huntObservation.id });
  await db.delete(huntRun).where(lt(huntRun.startedAt, new Date(Date.now() - 90 * 86_400_000)));
  return { siem: `${siemOk}/${siems.length}`, users: users.length, findings, purged: purged.length };
}

// ---------- Lecture ----------

export interface FindingRow {
  id: number;
  assetId: number | null;
  asset: string | null;
  kind: string;
  indicatorType: string;
  indicator: string;
  source: string;
  threat: string;
  malware: string;
  severity: string;
  confidence: number | null;
  evidence: Record<string, unknown>;
  firstSeen: string;
  lastSeen: string;
  status: string;
}

export async function listFindings(orgId: string, open = false, limit = 300): Promise<FindingRow[]> {
  const rows = await getDb()
    .select({ f: huntFinding, a: huntAsset.name })
    .from(huntFinding)
    .leftJoin(huntAsset, eq(huntAsset.id, huntFinding.assetId))
    .where(and(eq(huntFinding.orgId, orgId), open ? inArray(huntFinding.status, ["nouveau", "en_cours"]) : undefined))
    .orderBy(sql`case ${huntFinding.severity} when 'critique' then 0 when 'haute' then 1 when 'moyenne' then 2 else 3 end`, desc(huntFinding.lastSeen))
    .limit(limit);
  return rows.map(({ f, a }) => ({
    id: f.id,
    assetId: f.assetId,
    asset: a,
    kind: f.kind,
    indicatorType: f.indicatorType,
    indicator: f.indicator,
    source: f.source,
    threat: f.threat,
    malware: f.malware,
    severity: f.severity,
    confidence: f.confidence,
    evidence: f.evidence,
    firstSeen: f.firstSeen.toISOString(),
    lastSeen: f.lastSeen.toISOString(),
    status: f.status,
  }));
}

export const FINDING_STATUSES = ["nouveau", "en_cours", "resolu", "faux_positif"] as const;
export async function setFindingStatus(orgId: string, id: number, status: string): Promise<void> {
  if (!FINDING_STATUSES.includes(status as (typeof FINDING_STATUSES)[number])) throw new HuntError("Statut inconnu.");
  const r = await getDb()
    .update(huntFinding)
    .set({ status, updatedAt: new Date() })
    .where(and(eq(huntFinding.orgId, orgId), eq(huntFinding.id, id)))
    .returning({ id: huntFinding.id });
  if (!r.length) throw new HuntError("Détection introuvable.", 404);
}

export async function observationsOf(orgId: string, assetId: number, kind?: string, limit = 80) {
  return getDb()
    .select({ kind: huntObservation.kind, value: huntObservation.value, context: huntObservation.context, count: huntObservation.count, lastSeen: huntObservation.lastSeen })
    .from(huntObservation)
    .where(and(eq(huntObservation.orgId, orgId), eq(huntObservation.assetId, assetId), kind ? eq(huntObservation.kind, kind) : undefined))
    .orderBy(desc(huntObservation.count))
    .limit(limit);
}

export async function whoSaw(orgId: string, value: string) {
  return getDb()
    .select({ asset: huntAsset.name, kind: huntObservation.kind, value: huntObservation.value, context: huntObservation.context, count: huntObservation.count, lastSeen: huntObservation.lastSeen })
    .from(huntObservation)
    .innerJoin(huntAsset, eq(huntAsset.id, huntObservation.assetId))
    .where(and(eq(huntObservation.orgId, orgId), sql`${huntObservation.value} ilike ${`%${value.slice(0, 200)}%`}`))
    .limit(40);
}

/** Fuites de données qui concernent l'utilisateur : darkweb (rapprochements) et comptes exposés. */
export async function leaksSummary(orgId: string) {
  const db = getDb();
  const dark = await db
    .select({ title: leakEvent.title, status: leakEvent.status, score: leakMatch.score, mode: leakMatch.mode, count: leakMatch.indicatorCount, source: leakSource.name, postedAt: leakEvent.postedAt, classes: leakEvent.dataClasses })
    .from(leakMatch)
    .innerJoin(leakEvent, eq(leakEvent.id, leakMatch.eventId))
    .innerJoin(leakSource, eq(leakSource.id, leakEvent.sourceId))
    .where(and(eq(leakMatch.orgId, orgId), ne(leakEvent.status, "false_positive")))
    .orderBy(desc(leakMatch.score))
    .limit(20);
  const accounts = await db
    .select({ status: watchAccount.status, n: sql<number>`count(*)::int`, stealers: sql<number>`sum(jsonb_array_length(${watchAccount.stealers}))::int` })
    .from(watchAccount)
    .where(eq(watchAccount.orgId, orgId))
    .groupBy(watchAccount.status);
  const exfil = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(huntFinding)
    .where(and(eq(huntFinding.orgId, orgId), inArray(huntFinding.kind, ["exfiltration", "tunnel_dns", "tor"]), inArray(huntFinding.status, ["nouveau", "en_cours"])));
  return {
    darkweb: dark.map((d) => ({ ...d, postedAt: d.postedAt?.toISOString() ?? null })),
    accounts: Object.fromEntries(accounts.map((a) => [a.status, a.n])),
    infostealers: accounts.reduce((s, a) => s + (a.stealers ?? 0), 0),
    exfiltration: exfil[0]?.n ?? 0,
  };
}

export async function overview(orgId: string) {
  const db = getDb();
  const [assets, findings, siem, runs, idx, leaks] = await Promise.all([
    listAssets(orgId),
    listFindings(orgId, false, 300),
    getSiem(orgId),
    db.select().from(huntRun).where(eq(huntRun.orgId, orgId)).orderBy(desc(huntRun.startedAt)).limit(10),
    iocIndex().catch(() => null),
    leaksSummary(orgId),
  ]);
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(huntObservation).where(eq(huntObservation.orgId, orgId));
  return {
    assets,
    findings,
    siem,
    leaks,
    observations: n,
    iocs: idx ? { total: idx.idx.size, sources: idx.sources, generatedAt: idx.generatedAt } : null,
    runs: runs.map((r) => ({ id: r.id, kind: r.kind, trigger: r.trigger, stats: r.stats, report: r.report, model: r.model, error: r.error, startedAt: r.startedAt.toISOString(), finishedAt: r.finishedAt?.toISOString() ?? null })),
  };
}


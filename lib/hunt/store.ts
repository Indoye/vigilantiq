/**
 * Threat Hunting — base de données : équipements et clés d'agent, réception des données de l'agent,
 * connecteur SIEM/EDR, chasse (correspondance avec tous les IOC), détections, fuites et purge.
 */
import { and, desc, eq, gt, inArray, isNotNull, lt, ne, sql } from "drizzle-orm";
import { dbConfigured, getDb } from "@/db";
import { huntAsset, huntFinding, huntObservation, huntRun, huntSiem, leakEvent, leakMatch, leakSource, watchAccount, watchItem } from "@/db/schema";
import { verifySignature } from "../cti/leaks.ts";
import { serverSecret } from "../cti/leakstore.ts";
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

async function ownDomains(userId: string): Promise<string[]> {
  const rows = await getDb()
    .select({ v: watchItem.value })
    .from(watchItem)
    .where(and(eq(watchItem.userId, userId), eq(watchItem.kind, "domain"), isNotNull(watchItem.verifiedAt)));
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

export async function listAssets(userId: string): Promise<AssetRow[]> {
  const db = getDb();
  const rows = await db.select().from(huntAsset).where(eq(huntAsset.userId, userId)).orderBy(huntAsset.name);
  const obs = await db.select({ a: huntObservation.assetId, n: sql<number>`count(*)::int` }).from(huntObservation).where(eq(huntObservation.userId, userId)).groupBy(huntObservation.assetId);
  const fin = await db
    .select({ a: huntFinding.assetId, s: huntFinding.severity, n: sql<number>`count(*)::int` })
    .from(huntFinding)
    .where(and(eq(huntFinding.userId, userId), inArray(huntFinding.status, ["nouveau", "en_cours"])))
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
export async function createAsset(userId: string, f: { name?: unknown; kind?: unknown }): Promise<{ id: number; key: string }> {
  const name = typeof f.name === "string" ? f.name.trim().slice(0, 80) : "";
  if (!name) throw new HuntError("Nom de l’équipement obligatoire.");
  const kind = ASSET_KINDS.includes(f.kind as (typeof ASSET_KINDS)[number]) ? (f.kind as string) : "poste";
  const db = getDb();
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(huntAsset).where(eq(huntAsset.userId, userId));
  if (n >= MAX_ASSETS()) throw new HuntError(`Limite de ${MAX_ASSETS()} équipements atteinte.`);
  const salt = newSalt();
  const [row] = await db.insert(huntAsset).values({ userId, name, kind, source: "agent", keySalt: salt }).onConflictDoNothing().returning({ id: huntAsset.id });
  if (!row) throw new HuntError("Un équipement porte déjà ce nom.");
  return { id: row.id, key: agentKey(serverSecret(), row.id, salt) };
}

export async function rotateAssetKey(userId: string, id: number): Promise<string> {
  const salt = newSalt();
  const res = await getDb()
    .update(huntAsset)
    .set({ keySalt: salt, source: "agent" })
    .where(and(eq(huntAsset.userId, userId), eq(huntAsset.id, id)))
    .returning({ id: huntAsset.id });
  if (!res.length) throw new HuntError("Équipement introuvable.", 404);
  return agentKey(serverSecret(), id, salt);
}

export async function deleteAsset(userId: string, id: number): Promise<void> {
  await getDb().delete(huntAsset).where(and(eq(huntAsset.userId, userId), eq(huntAsset.id, id)));
}

// ---------- Observables et détections ----------

async function saveObservations(userId: string, assetId: number, obs: Obs[]): Promise<void> {
  const db = getDb();
  const now = new Date();
  for (let i = 0; i < obs.length; i += 500) {
    await db
      .insert(huntObservation)
      .values(obs.slice(i, i + 500).map((o) => ({ userId, assetId, kind: o.kind, value: o.value.slice(0, 800), context: o.context })))
      .onConflictDoUpdate({
        target: [huntObservation.assetId, huntObservation.kind, huntObservation.value],
        set: { lastSeen: now, count: sql`${huntObservation.count} + 1`, context: sql`excluded.context` },
      });
  }
}

/** Enregistre les détections ; une détection résolue qui réapparaît redevient « nouveau ». */
async function saveFindings(userId: string, assetId: number | null, drafts: FindingDraft[]): Promise<number> {
  if (!drafts.length) return 0;
  const db = getDb();
  const now = new Date();
  let created = 0;
  for (const d of drafts) {
    const [r] = await db
      .insert(huntFinding)
      .values({ userId, assetId, ...d, indicator: d.indicator.slice(0, 800), firstSeen: now, lastSeen: now })
      .onConflictDoUpdate({
        target: [huntFinding.userId, huntFinding.assetId, huntFinding.kind, huntFinding.indicator],
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

async function ingest(userId: string, assetId: number, obs: Obs[]): Promise<{ observations: number; findings: number }> {
  await saveObservations(userId, assetId, obs);
  const { idx } = await iocIndex();
  const drafts = hunt(obs, idx, { ownDomains: await ownDomains(userId) });
  return { observations: obs.length, findings: await saveFindings(userId, assetId, drafts) };
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
  const r = await ingest(asset.userId, asset.id, obs);
  return { ...r, counts };
}

// ---------- Connecteur SIEM/EDR ----------

export type SiemType = "elastic" | "splunk";
export interface SiemAuth {
  kind: "basic" | "apikey" | "bearer";
  user?: string;
  password?: string;
  token?: string;
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
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new HuntError("Adresse du SIEM invalide.");
  }
  if (u.protocol !== "https:") throw new HuntError("Le SIEM doit être joignable en HTTPS.");
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(h) || h === "::1" || h.startsWith("fd") || h.startsWith("fe80"))
    throw new HuntError("Adresse locale ou privée refusée : le SIEM doit être joignable depuis Internet (par exemple via un proxy inverse).");
  return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
}

export async function getSiem(userId: string): Promise<SiemView | null> {
  const [r] = await getDb().select().from(huntSiem).where(eq(huntSiem.userId, userId));
  if (!r) return null;
  let authKind = "?";
  try {
    authKind = (JSON.parse(unseal(serverSecret(), r.authEnc)) as SiemAuth).kind;
  } catch {
    /* clé serveur changée : identifiants à ressaisir */
  }
  return { type: r.type as SiemType, url: r.url, index: r.index, authKind, enabled: r.enabled, lastPullAt: r.lastPullAt?.toISOString() ?? null, lastError: r.lastError, lastStats: r.lastStats ?? null };
}

export async function saveSiem(userId: string, f: Record<string, unknown>): Promise<void> {
  const type = f.type === "splunk" ? "splunk" : f.type === "elastic" ? "elastic" : null;
  if (!type) throw new HuntError("Type de SIEM inconnu.");
  const url = checkSiemUrl(String(f.url ?? ""));
  const index = typeof f.index === "string" ? f.index.trim().slice(0, 200) : "";
  const a = (f.auth ?? {}) as Record<string, unknown>;
  const kind = a.kind === "basic" || a.kind === "apikey" || a.kind === "bearer" ? a.kind : null;
  if (!kind) throw new HuntError("Mode d’authentification inconnu.");
  const auth: SiemAuth = kind === "basic" ? { kind, user: String(a.user ?? ""), password: String(a.password ?? "") } : { kind, token: String(a.token ?? "") };
  if ((kind === "basic" && (!auth.user || !auth.password)) || (kind !== "basic" && !auth.token)) throw new HuntError("Identifiants incomplets.");
  const authEnc = seal(serverSecret(), JSON.stringify(auth));
  await getDb()
    .insert(huntSiem)
    .values({ userId, type, url, index, authEnc, enabled: true })
    .onConflictDoUpdate({ target: huntSiem.userId, set: { type, url, index, authEnc, enabled: true, lastError: null, updatedAt: new Date() } });
}

export async function deleteSiem(userId: string): Promise<void> {
  await getDb().delete(huntSiem).where(eq(huntSiem.userId, userId));
}

function authHeader(a: SiemAuth): string {
  if (a.kind === "basic") return `Basic ${Buffer.from(`${a.user}:${a.password}`).toString("base64")}`;
  if (a.kind === "apikey") return `ApiKey ${a.token}`;
  return `Bearer ${a.token}`;
}

/** Récupère les événements récents du SIEM (24 h au plus, depuis la dernière collecte). */
export async function fetchSiemEvents(type: SiemType, url: string, index: string, auth: SiemAuth, since: Date, max = 3000): Promise<Record<string, unknown>[]> {
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
export async function pullSiem(userId: string): Promise<{ events: number; hosts: number; observations: number; findings: number }> {
  const db = getDb();
  const [cfg] = await db.select().from(huntSiem).where(eq(huntSiem.userId, userId));
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
      await db.insert(huntAsset).values({ userId, name, kind: "poste", source: "siem", hostname: name }).onConflictDoNothing();
      const [asset] = await db.select().from(huntAsset).where(and(eq(huntAsset.userId, userId), eq(huntAsset.name, name)));
      await db.update(huntAsset).set({ lastSeenAt: new Date() }).where(eq(huntAsset.id, asset.id));
      // Dédoublonnage entre événements d'un même hôte
      const uniq = new Map(obs.map((o) => [`${o.kind}|${o.value}`, o]));
      const r = await ingest(userId, asset.id, [...uniq.values()].slice(0, 8000));
      observations += r.observations;
      findings += r.findings;
    }
    const stats = { events: events.length, hosts: byHost.size, observations, findings };
    await db.update(huntSiem).set({ lastPullAt: new Date(), lastError: null, lastStats: stats }).where(eq(huntSiem.userId, userId));
    return stats;
  } catch (e) {
    await db.update(huntSiem).set({ lastError: msg(e).slice(0, 300) }).where(eq(huntSiem.userId, userId));
    throw e instanceof HuntError ? e : new HuntError(`Collecte SIEM impossible : ${msg(e)}`, 502);
  }
}

// ---------- Chasse rétroactive ----------

/** Rejoue tous les observables récents contre les IOC du moment (un IOC publié aujourd'hui révèle une connexion d'hier). */
export async function huntUser(userId: string, trigger = "manuel"): Promise<{ observations: number; findings: number; iocs: number; runId: number }> {
  const db = getDb();
  const [run] = await db.insert(huntRun).values({ userId, kind: "chasse", trigger }).returning({ id: huntRun.id });
  try {
    const { idx } = await iocIndex();
    const own = await ownDomains(userId);
    const since = new Date(Date.now() - OBS_RETENTION_DAYS() * 86_400_000);
    const rows = await db
      .select()
      .from(huntObservation)
      .where(and(eq(huntObservation.userId, userId), gt(huntObservation.lastSeen, since)));
    const byAsset = new Map<number, Obs[]>();
    for (const r of rows) byAsset.set(r.assetId, [...(byAsset.get(r.assetId) ?? []), { kind: r.kind as Obs["kind"], value: r.value, context: r.context as Obs["context"] }]);
    let findings = 0;
    for (const [assetId, obs] of byAsset) findings += await saveFindings(userId, assetId, hunt(obs, idx, { ownDomains: own }));
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
  const siems = await db.select({ u: huntSiem.userId }).from(huntSiem).where(eq(huntSiem.enabled, true));
  let siemOk = 0;
  for (const s of siems) {
    try {
      await pullSiem(s.u);
      siemOk++;
    } catch (e) {
      console.error(`[chasse] SIEM ${s.u} : ${msg(e)}`);
    }
  }
  const users = await db.selectDistinct({ u: huntObservation.userId }).from(huntObservation);
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

export async function listFindings(userId: string, open = false, limit = 300): Promise<FindingRow[]> {
  const rows = await getDb()
    .select({ f: huntFinding, a: huntAsset.name })
    .from(huntFinding)
    .leftJoin(huntAsset, eq(huntAsset.id, huntFinding.assetId))
    .where(and(eq(huntFinding.userId, userId), open ? inArray(huntFinding.status, ["nouveau", "en_cours"]) : undefined))
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
export async function setFindingStatus(userId: string, id: number, status: string): Promise<void> {
  if (!FINDING_STATUSES.includes(status as (typeof FINDING_STATUSES)[number])) throw new HuntError("Statut inconnu.");
  const r = await getDb()
    .update(huntFinding)
    .set({ status, updatedAt: new Date() })
    .where(and(eq(huntFinding.userId, userId), eq(huntFinding.id, id)))
    .returning({ id: huntFinding.id });
  if (!r.length) throw new HuntError("Détection introuvable.", 404);
}

export async function observationsOf(userId: string, assetId: number, kind?: string, limit = 80) {
  return getDb()
    .select({ kind: huntObservation.kind, value: huntObservation.value, context: huntObservation.context, count: huntObservation.count, lastSeen: huntObservation.lastSeen })
    .from(huntObservation)
    .where(and(eq(huntObservation.userId, userId), eq(huntObservation.assetId, assetId), kind ? eq(huntObservation.kind, kind) : undefined))
    .orderBy(desc(huntObservation.count))
    .limit(limit);
}

export async function whoSaw(userId: string, value: string) {
  return getDb()
    .select({ asset: huntAsset.name, kind: huntObservation.kind, value: huntObservation.value, context: huntObservation.context, count: huntObservation.count, lastSeen: huntObservation.lastSeen })
    .from(huntObservation)
    .innerJoin(huntAsset, eq(huntAsset.id, huntObservation.assetId))
    .where(and(eq(huntObservation.userId, userId), sql`${huntObservation.value} ilike ${`%${value.slice(0, 200)}%`}`))
    .limit(40);
}

/** Fuites de données qui concernent l'utilisateur : darkweb (rapprochements) et comptes exposés. */
export async function leaksSummary(userId: string) {
  const db = getDb();
  const dark = await db
    .select({ title: leakEvent.title, status: leakEvent.status, score: leakMatch.score, mode: leakMatch.mode, count: leakMatch.indicatorCount, source: leakSource.name, postedAt: leakEvent.postedAt, classes: leakEvent.dataClasses })
    .from(leakMatch)
    .innerJoin(leakEvent, eq(leakEvent.id, leakMatch.eventId))
    .innerJoin(leakSource, eq(leakSource.id, leakEvent.sourceId))
    .where(and(eq(leakMatch.userId, userId), ne(leakEvent.status, "false_positive")))
    .orderBy(desc(leakMatch.score))
    .limit(20);
  const accounts = await db
    .select({ status: watchAccount.status, n: sql<number>`count(*)::int`, stealers: sql<number>`sum(jsonb_array_length(${watchAccount.stealers}))::int` })
    .from(watchAccount)
    .where(eq(watchAccount.userId, userId))
    .groupBy(watchAccount.status);
  const exfil = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(huntFinding)
    .where(and(eq(huntFinding.userId, userId), inArray(huntFinding.kind, ["exfiltration", "tunnel_dns", "tor"]), inArray(huntFinding.status, ["nouveau", "en_cours"])));
  return {
    darkweb: dark.map((d) => ({ ...d, postedAt: d.postedAt?.toISOString() ?? null })),
    accounts: Object.fromEntries(accounts.map((a) => [a.status, a.n])),
    infostealers: accounts.reduce((s, a) => s + (a.stealers ?? 0), 0),
    exfiltration: exfil[0]?.n ?? 0,
  };
}

export async function overview(userId: string) {
  const db = getDb();
  const [assets, findings, siem, runs, idx, leaks] = await Promise.all([
    listAssets(userId),
    listFindings(userId, false, 300),
    getSiem(userId),
    db.select().from(huntRun).where(eq(huntRun.userId, userId)).orderBy(desc(huntRun.startedAt)).limit(10),
    iocIndex().catch(() => null),
    leaksSummary(userId),
  ]);
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(huntObservation).where(eq(huntObservation.userId, userId));
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


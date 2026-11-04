/**
 * Collecte des forums du dark web par Apify (Actor epctex/darkweb-scraper) et surveillance par motifs.
 *
 * Chaîne : source .onion → run Apify (sur l'infrastructure d'Apify, via Tor) → récupération du dataset →
 * masquage (lib/darkweb/redact) → index des pages du cluster → percolation contre les motifs de toutes les
 * organisations → correspondances isolées par organisation + alertes (e-mail avec les autres alertes de veille).
 *
 * Variables : APIFY_TOKEN (obligatoire), DARKWEB_ACTOR (epctex~darkweb-scraper par défaut),
 * DARKWEB_MAX_USD_PER_RUN (plafond de dépense par run, 2 USD par défaut), DARKWEB_MAX_PAGES (500 par défaut).
 */
import { createHash } from "node:crypto";
import { and, asc, desc, eq, inArray, lt, or, isNull, sql } from "drizzle-orm";
import { getDb } from "@/db";
import { ctiAlert, dwMatch, dwPattern, dwRun, dwSource } from "@/db/schema";
import { serverSecret } from "../cti/leakstore.ts";
import { emailHash, hostOf, isOnionUrl, redact } from "./redact.ts";
import {
  bulkIndex,
  deletePattern,
  highlightFor,
  normalizePattern,
  PATTERN_KINDS,
  patternQuery,
  percolate,
  putPattern,
  searchConfigured,
  searchPages,
  snippetsFor,
  type PageDoc,
  type PatternKind,
} from "./search.ts";

export class DarkwebError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

const APIFY = "https://api.apify.com/v2";
const actor = () => (process.env.DARKWEB_ACTOR || "epctex~darkweb-scraper").replace("/", "~");
export const apifyConfigured = () => Boolean(process.env.APIFY_TOKEN);
export const darkwebConfigured = () => apifyConfigured() && searchConfigured();
const MAX_PAGES = () => Math.max(10, Number(process.env.DARKWEB_MAX_PAGES || 500));
const MAX_USD = () => Math.max(0.1, Number(process.env.DARKWEB_MAX_USD_PER_RUN || 2));
const SEVERITIES = ["critique", "haute", "moyenne", "info"];

async function apify<T>(method: string, path: string, body?: unknown): Promise<T> {
  if (!apifyConfigured()) throw new DarkwebError("Apify n’est pas configuré (APIFY_TOKEN).", 409);
  const res = await fetch(`${APIFY}${path}`, {
    method,
    headers: { Authorization: `Bearer ${process.env.APIFY_TOKEN}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const j = (await res.json().catch(() => ({}))) as { data?: T; error?: { message?: string } } & T;
  if (!res.ok) throw new DarkwebError(`Apify : ${j.error?.message ?? `HTTP ${res.status}`}`, 502);
  return (j.data ?? j) as T;
}

// ---------- Sources (analystes de la plateforme) ----------

export async function listSources() {
  return getDb().select().from(dwSource).orderBy(asc(dwSource.id));
}

function sourceFields(b: Record<string, unknown>) {
  const url = String(b.url ?? "").trim();
  if (!isOnionUrl(url)) throw new DarkwebError("Adresse .onion v3 attendue (http://…56 caractères….onion/).");
  const label = String(b.label ?? "").trim().slice(0, 80) || hostOf(url).slice(0, 16);
  const keyword = String(b.keyword ?? "").trim().slice(0, 100);
  const maxDepth = Math.min(5, Math.max(0, Math.round(Number(b.maxDepth ?? 2)) || 0));
  const maxPages = Math.min(MAX_PAGES(), Math.max(1, Math.round(Number(b.maxPages ?? 200)) || 200));
  return { url, label, keyword, maxDepth, maxPages };
}

export async function createSource(b: Record<string, unknown>, by: string) {
  const [r] = await getDb()
    .insert(dwSource)
    .values({ ...sourceFields(b), createdBy: by })
    .returning();
  return r;
}

export async function updateSource(id: number, b: Record<string, unknown>) {
  const db = getDb();
  const [cur] = await db.select().from(dwSource).where(eq(dwSource.id, id));
  if (!cur) throw new DarkwebError("Source introuvable.", 404);
  const f = sourceFields({ ...cur, ...b });
  await db
    .update(dwSource)
    .set({ ...f, active: typeof b.active === "boolean" ? b.active : cur.active })
    .where(eq(dwSource.id, id));
}

export async function deleteSource(id: number) {
  await getDb().delete(dwSource).where(eq(dwSource.id, id));
}

// ---------- Runs ----------

export async function startRun(sourceId: number, trigger: "cron" | "manuel"): Promise<number> {
  const db = getDb();
  const [s] = await db.select().from(dwSource).where(eq(dwSource.id, sourceId));
  if (!s) throw new DarkwebError("Source introuvable.", 404);
  const input: Record<string, unknown> = { startUrls: [s.url], maxDepth: s.maxDepth, maxPages: Math.min(s.maxPages, MAX_PAGES()) };
  if (s.keyword) input.search = s.keyword;
  // Plafond de dépense par run (Actor facturé à l'événement)
  const run = await apify<{ id: string; defaultDatasetId: string; status: string }>(
    "POST",
    `/acts/${encodeURIComponent(actor())}/runs?maxTotalChargeUsd=${MAX_USD()}&maxItems=${Math.min(s.maxPages, MAX_PAGES())}`,
    input,
  );
  const [r] = await db
    .insert(dwRun)
    .values({ sourceId, apifyRunId: run.id, datasetId: run.defaultDatasetId ?? "", status: run.status || "RUNNING", trigger })
    .returning({ id: dwRun.id });
  await db.update(dwSource).set({ lastRunAt: new Date() }).where(eq(dwSource.id, sourceId));
  return r.id;
}

export async function listRuns(limit = 30) {
  return getDb()
    .select({ run: dwRun, label: dwSource.label })
    .from(dwRun)
    .leftJoin(dwSource, eq(dwSource.id, dwRun.sourceId))
    .orderBy(desc(dwRun.startedAt))
    .limit(limit);
}

interface ApifyItem {
  url?: unknown;
  data?: unknown;
  emails?: unknown;
  links?: unknown;
  searchKeywordFound?: unknown;
  createdAt?: unknown;
}

/** Transforme une page Apify en document masqué (les champs « misc » et « phones » de l'Actor sont ignorés). */
export function toPageDoc(item: ApifyItem, runId: string, sourceId: number | null): { id: string; doc: PageDoc } | null {
  const url = typeof item.url === "string" ? item.url.slice(0, 500) : "";
  if (!url) return null;
  const raw = typeof item.data === "string" ? item.data : "";
  const emails = Array.isArray(item.emails) ? item.emails.filter((e): e is string => typeof e === "string").slice(0, 2000) : [];
  const r = redact(raw, serverSecret(), emails);
  const links = Array.isArray(item.links) ? item.links.filter((l): l is string => typeof l === "string") : [];
  const onion = [...new Set(links.map(hostOf).filter((h) => h.endsWith(".onion")))].slice(0, 200);
  const created = typeof item.createdAt === "string" && !Number.isNaN(Date.parse(item.createdAt)) ? new Date(item.createdAt) : new Date();
  return {
    id: createHash("sha256").update(url).digest("hex").slice(0, 40),
    doc: {
      url,
      host: hostOf(url),
      source_id: sourceId,
      run_id: runId,
      text: r.text,
      email_hashes: r.emailHashes,
      email_domains: r.emailDomains,
      wallets: r.wallets,
      onion_links: onion,
      counts: r.counts,
      keyword_hit: item.searchKeywordFound === true,
      collected_at: created.toISOString(),
    },
  };
}

const TERMINAL = ["SUCCEEDED", "FAILED", "ABORTED", "TIMED-OUT"];

/** Fait avancer un run : statut Apify, puis ingestion du dataset par lots jusqu'au budget de temps. */
export async function advanceRun(id: number, deadline: number): Promise<{ status: string; ingested: number; matches: number }> {
  const db = getDb();
  const [r] = await db.select().from(dwRun).where(eq(dwRun.id, id));
  if (!r) throw new DarkwebError("Run introuvable.", 404);
  if (r.status === "INGESTED") return { status: r.status, ingested: r.ingested, matches: r.matches };
  let status = r.status;
  let datasetId = r.datasetId;
  let finishedAt = r.finishedAt;
  if (!TERMINAL.includes(status)) {
    const a = await apify<{ status: string; defaultDatasetId: string; finishedAt?: string | null }>("GET", `/actor-runs/${encodeURIComponent(r.apifyRunId)}`);
    status = a.status;
    datasetId = a.defaultDatasetId || datasetId;
    finishedAt = a.finishedAt ? new Date(a.finishedAt) : finishedAt;
    await db.update(dwRun).set({ status, datasetId, finishedAt }).where(eq(dwRun.id, id));
  }
  // Les pages déjà produites sont ingérées même si le run a échoué ou atteint son plafond.
  let ingested = r.ingested;
  let matches = r.matches;
  const sourceId = r.sourceId;
  while (Date.now() < deadline && datasetId) {
    const items = await apify<ApifyItem[]>("GET", `/datasets/${encodeURIComponent(datasetId)}/items?clean=true&format=json&offset=${ingested}&limit=100`);
    const list = Array.isArray(items) ? items : [];
    if (!list.length) break;
    const docs = list.map((it) => toPageDoc(it, r.apifyRunId, sourceId)).filter((d): d is { id: string; doc: PageDoc } => d !== null);
    await bulkIndex(docs);
    matches += await matchDocs(docs);
    ingested += list.length;
    await db.update(dwRun).set({ ingested, matches, pages: sql`greatest(${dwRun.pages}, ${ingested})` }).where(eq(dwRun.id, id));
    if (list.length < 100) break;
  }
  if (TERMINAL.includes(status) && Date.now() < deadline) {
    const error = status === "SUCCEEDED" ? null : `Run Apify terminé : ${status} (pages produites ingérées).`;
    status = "INGESTED";
    await db.update(dwRun).set({ status, ingestedAt: new Date(), error }).where(eq(dwRun.id, id));
  }
  return { status, ingested, matches };
}

// ---------- Correspondances ----------

/** Percolation d'un lot de pages ; enregistre les correspondances et crée les alertes. Renvoie le nombre de nouvelles. */
async function matchDocs(docs: { id: string; doc: PageDoc }[]): Promise<number> {
  let created = 0;
  for (let i = 0; i < docs.length; i += 25) {
    const batch = docs.slice(i, i + 25);
    const hits = await percolate(batch.map((d) => d.doc));
    if (!hits.length) continue;
    const ids = [...new Set(hits.map((h) => h.patternId))];
    const pats = await getDb().select().from(dwPattern).where(and(inArray(dwPattern.id, ids), eq(dwPattern.active, true)));
    const byId = new Map(pats.map((p) => [p.id, p]));
    for (const p of pats) {
      const docIds = hits.filter((h) => h.patternId === p.id && h.orgId === p.orgId).map((h) => batch[h.slot]?.id).filter(Boolean) as string[];
      if (!docIds.length) continue;
      const snips = await snippetsFor(patternQuery(p.kind as PatternKind, p.value), docIds, highlightFor(p.kind as PatternKind, p.display)).catch(() => new Map<string, string>());
      for (const docId of docIds) {
        const d = batch.find((x) => x.id === docId)!;
        created += await recordMatch(byId.get(p.id)!, docId, d.doc.url, d.doc.host, snips.get(docId) || d.doc.text.slice(0, 300), d.doc.collected_at, d.doc.counts);
      }
    }
  }
  return created;
}

async function recordMatch(
  p: typeof dwPattern.$inferSelect,
  docId: string,
  url: string,
  host: string,
  snippet: string,
  collectedAt: string,
  counts: Record<string, number> = {},
  alert = true,
): Promise<number> {
  const db = getDb();
  const ins = await db
    .insert(dwMatch)
    .values({ orgId: p.orgId, patternId: p.id, docId, url, host, snippet: snippet.slice(0, 1200), collectedAt: new Date(collectedAt) })
    .onConflictDoNothing()
    .returning({ id: dwMatch.id });
  if (!ins.length) return 0;
  await db
    .update(dwPattern)
    .set({ matchCount: sql`${dwPattern.matchCount} + 1`, lastMatchAt: new Date() })
    .where(eq(dwPattern.id, p.id));
  if (alert) {
    await db
      .insert(ctiAlert)
      .values({
        orgId: p.orgId,
        source: "dw_forum",
        externalId: `dw:${p.id}:${docId}`,
        watchValue: p.display,
        severity: p.severity,
        title: `« ${p.name} » repéré sur ${host || "un site .onion"}`,
        detail: { snippet: snippet.slice(0, 600), url, kind: p.kind, credentials: counts.credentials ?? 0, secrets: counts.secrets ?? 0 },
        url: "",
      })
      .onConflictDoNothing();
  }
  return 1;
}

// ---------- Motifs (organisation) ----------

const maskEmail = (e: string) => {
  const [u, d] = e.split("@");
  return `${u.slice(0, 1)}${"•".repeat(Math.max(2, Math.min(6, u.length - 1)))}@${d}`;
};

export async function listPatterns(orgId: string) {
  return getDb().select().from(dwPattern).where(eq(dwPattern.orgId, orgId)).orderBy(desc(dwPattern.createdAt));
}

export async function createPattern(orgId: string, by: string, b: Record<string, unknown>) {
  const kind = String(b.kind ?? "") as PatternKind;
  if (!PATTERN_KINDS.includes(kind)) throw new DarkwebError("Type de motif inconnu.");
  const db = getDb();
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(dwPattern).where(eq(dwPattern.orgId, orgId));
  if (n >= 200) throw new DarkwebError("200 motifs au plus par organisation.");
  let value: string;
  try {
    value = normalizePattern(kind, String(b.value ?? ""));
  } catch (e) {
    throw new DarkwebError(e instanceof Error ? e.message : "Motif invalide.");
  }
  const display = kind === "email" ? maskEmail(value) : value;
  if (kind === "email") value = emailHash(value, serverSecret());
  const name = String(b.name ?? "").trim().slice(0, 80) || display;
  const severity = SEVERITIES.includes(String(b.severity)) ? String(b.severity) : "haute";
  const [p] = await db.insert(dwPattern).values({ orgId, name, kind, value, display, severity, createdBy: by }).returning();
  try {
    await putPattern({ id: p.id, orgId, kind, value, active: true });
  } catch (e) {
    await db.delete(dwPattern).where(eq(dwPattern.id, p.id));
    throw new DarkwebError(e instanceof Error ? e.message : "Cluster de recherche indisponible.", 502);
  }
  // Recherche rétroactive dans le corpus déjà collecté (sans alerte par page : un seul résumé)
  const retro = await backfill(p).catch((e) => {
    console.error(`[dark web] recherche rétroactive : ${e instanceof Error ? e.message : e}`);
    return 0;
  });
  return { pattern: p, retro };
}

async function backfill(p: typeof dwPattern.$inferSelect): Promise<number> {
  const r = await searchPages(patternQuery(p.kind as PatternKind, p.value), { size: 200, highlightQuery: highlightFor(p.kind as PatternKind, p.display) });
  let n = 0;
  for (const h of r.hits) n += await recordMatch(p, h.id, h.url, h.host, h.snippet, h.collectedAt, h.counts, false);
  if (n) {
    await getDb()
      .insert(ctiAlert)
      .values({
        orgId: p.orgId,
        source: "dw_forum",
        externalId: `dw:${p.id}:retro`,
        watchValue: p.display,
        severity: p.severity,
        title: `« ${p.name} » : ${n} page${n > 1 ? "s" : ""} déjà présente${n > 1 ? "s" : ""} dans le corpus du dark web`,
        detail: { total: r.total, kind: p.kind },
        url: "",
      })
      .onConflictDoNothing();
  }
  return n;
}

export async function updatePattern(orgId: string, id: number, b: Record<string, unknown>) {
  const db = getDb();
  const [p] = await db.select().from(dwPattern).where(and(eq(dwPattern.orgId, orgId), eq(dwPattern.id, id)));
  if (!p) throw new DarkwebError("Motif introuvable.", 404);
  const set: Partial<typeof dwPattern.$inferInsert> = {};
  if (typeof b.name === "string" && b.name.trim()) set.name = b.name.trim().slice(0, 80);
  if (SEVERITIES.includes(String(b.severity))) set.severity = String(b.severity);
  if (typeof b.active === "boolean") set.active = b.active;
  await db.update(dwPattern).set(set).where(eq(dwPattern.id, id));
  if (typeof b.active === "boolean") await putPattern({ id, orgId, kind: p.kind as PatternKind, value: p.value, active: b.active });
}

export async function removePattern(orgId: string, id: number) {
  const db = getDb();
  const [p] = await db.select({ id: dwPattern.id }).from(dwPattern).where(and(eq(dwPattern.orgId, orgId), eq(dwPattern.id, id)));
  if (!p) throw new DarkwebError("Motif introuvable.", 404);
  await deletePattern(id);
  await db.delete(dwPattern).where(eq(dwPattern.id, id));
}

export async function listMatches(orgId: string, opts: { status?: string; patternId?: number; limit?: number } = {}) {
  const conds = [eq(dwMatch.orgId, orgId)];
  if (opts.status) conds.push(eq(dwMatch.status, opts.status));
  if (opts.patternId) conds.push(eq(dwMatch.patternId, opts.patternId));
  return getDb()
    .select({ m: dwMatch, name: dwPattern.name, kind: dwPattern.kind, severity: dwPattern.severity })
    .from(dwMatch)
    .innerJoin(dwPattern, eq(dwPattern.id, dwMatch.patternId))
    .where(and(...conds))
    .orderBy(desc(dwMatch.createdAt))
    .limit(Math.min(opts.limit ?? 100, 500));
}

export async function setMatchStatus(orgId: string, id: number, status: string) {
  if (!["nouvelle", "traitee", "faux_positif"].includes(status)) throw new DarkwebError("Statut inconnu.");
  await getDb()
    .update(dwMatch)
    .set({ status })
    .where(and(eq(dwMatch.orgId, orgId), eq(dwMatch.id, id)));
}

/** Recherche ad hoc d'un analyste dans le corpus (texte déjà masqué). */
export async function adhocSearch(kind: string, value: string) {
  if (!PATTERN_KINDS.includes(kind as PatternKind)) throw new DarkwebError("Type de recherche inconnu.");
  let v: string;
  try {
    v = normalizePattern(kind as PatternKind, value);
  } catch (e) {
    throw new DarkwebError(e instanceof Error ? e.message : "Recherche invalide.");
  }
  if (kind === "email") v = emailHash(v, serverSecret());
  return searchPages(patternQuery(kind as PatternKind, v), { size: 30 });
}

// ---------- Passe quotidienne ----------

/** Ingère les runs en cours ou terminés, puis lance les sources actives non collectées depuis 20 h. */
export async function darkwebDaily(budgetMs = 150_000): Promise<Record<string, unknown>> {
  if (!darkwebConfigured()) return { skipped: "Apify ou cluster de recherche non configuré" };
  const deadline = Date.now() + budgetMs;
  const db = getDb();
  const pending = await db.select({ id: dwRun.id }).from(dwRun).where(sql`${dwRun.status} <> 'INGESTED'`).orderBy(asc(dwRun.startedAt)).limit(20);
  let ingested = 0;
  let matches = 0;
  const errors: string[] = [];
  for (const p of pending) {
    if (Date.now() > deadline) break;
    try {
      const r = await advanceRun(p.id, deadline);
      ingested += r.ingested;
      matches += r.matches;
    } catch (e) {
      const m = e instanceof Error ? e.message : String(e);
      errors.push(m);
      await db.update(dwRun).set({ error: m.slice(0, 300) }).where(eq(dwRun.id, p.id));
    }
  }
  const due = await db
    .select({ id: dwSource.id })
    .from(dwSource)
    .where(and(eq(dwSource.active, true), or(isNull(dwSource.lastRunAt), lt(dwSource.lastRunAt, new Date(Date.now() - 20 * 3_600_000)))))
    .limit(Number(process.env.DARKWEB_SOURCES_PER_DAY || 10));
  let started = 0;
  for (const s of due) {
    try {
      await startRun(s.id, "cron");
      started++;
    } catch (e) {
      errors.push(e instanceof Error ? e.message : String(e));
    }
  }
  return { ingested, matches, started, errors: errors.slice(0, 5) };
}

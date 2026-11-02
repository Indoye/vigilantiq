/**
 * Fuites du darkweb — base de données : sources et clés d'ingestion, file, événements, corrélation avec les
 * listes de surveillance, alertes « darkweb », qualification par les analystes et purge.
 */
import { createHash, createHmac } from "node:crypto";
import { and, desc, eq, gt, inArray, isNotNull, lt, ne, or, sql } from "drizzle-orm";
import { dbConfigured, getDb } from "@/db";
import { ctiAlert, ingestJob, leakEvent, leakIndicator, leakMatch, leakSource, watchAccount, watchItem } from "@/db/schema";
import { containsTerm, type AlertDraft } from "./match.ts";
import {
  ingestKey,
  isLookalike,
  keyMatches,
  keyedHash,
  leakScore,
  newSalt,
  parseIngestKey,
  parseIncoming,
  RELIABILITY,
  severityOf,
  SOURCE_KINDS,
  STATUS_FR,
  STATUSES,
  verifySignature,
  type LeakStatus,
  type MinEvent,
  type Reliability,
  type SourceKind,
} from "./leaks.ts";
import { saveDrafts } from "./store.ts";

export class LeakError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

// ---------- Secrets dérivés ----------

/** Secret serveur des fuites : LEAK_INGEST_SECRET, sinon celui des sessions. Le changer révoque toutes les clés. */
function serverSecret(): string {
  const s = process.env.LEAK_INGEST_SECRET || process.env.BETTER_AUTH_SECRET;
  if (s) return s;
  if (process.env.DATABASE_URL) return createHash("sha256").update(`vigilantiq:session:${process.env.DATABASE_URL}`).digest("base64url");
  throw new LeakError("Secret serveur absent (LEAK_INGEST_SECRET).", 500);
}
/** « Poivre » des empreintes d'identifiants : dérivé du secret serveur, jamais stocké. */
export const pepper = () => createHmac("sha256", serverSecret()).update("vigilantiq:leak-pepper").digest("hex");

// ---------- Analystes ----------

/** Analystes autorisés à qualifier les fuites et gérer les sources : VIGILANTIQ_ANALYSTS = « a@x.sn, b@x.sn ». */
export function isAnalyst(email: string | null | undefined): boolean {
  if (!email) return false;
  const list = (process.env.VIGILANTIQ_ANALYSTS ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  return list.includes(email.toLowerCase());
}

// ---------- Sources ----------

export interface SourceRow {
  id: number;
  name: string;
  kind: string;
  reliability: string;
  language: string;
  active: boolean;
  hasKey: boolean;
  createdAt: string;
  lastIngestAt: string | null;
  events: number;
}

export async function listSources(): Promise<SourceRow[]> {
  const db = getDb();
  const rows = await db.select().from(leakSource).orderBy(leakSource.name);
  const counts = await db.select({ id: leakEvent.sourceId, n: sql<number>`count(*)::int` }).from(leakEvent).groupBy(leakEvent.sourceId);
  const by = new Map(counts.map((c) => [c.id, c.n]));
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    kind: r.kind,
    reliability: r.reliability,
    language: r.language,
    active: r.active,
    hasKey: Boolean(r.keySalt),
    createdAt: r.createdAt.toISOString(),
    lastIngestAt: r.lastIngestAt?.toISOString() ?? null,
    events: by.get(r.id) ?? 0,
  }));
}

function checkSourceFields(f: { name?: unknown; kind?: unknown; reliability?: unknown; language?: unknown }) {
  const name = typeof f.name === "string" ? f.name.trim().slice(0, 80) : "";
  if (!name) throw new LeakError("Nom de la source obligatoire.");
  if (!SOURCE_KINDS.includes(f.kind as SourceKind)) throw new LeakError("Type de source inconnu.");
  const reliability = RELIABILITY.includes(f.reliability as Reliability) ? (f.reliability as string) : "F";
  const language = typeof f.language === "string" ? f.language.trim().slice(0, 20) : "";
  return { name, kind: f.kind as string, reliability, language };
}

/** Crée une source ; la clé d'ingestion est renvoyée une seule fois (elle n'est pas stockée). */
export async function createSource(f: Record<string, unknown>, by: string): Promise<{ id: number; key: string | null }> {
  const v = checkSourceFields(f);
  const withKey = v.kind !== "manual";
  const salt = withKey ? newSalt() : null;
  const [row] = await getDb().insert(leakSource).values({ ...v, keySalt: salt, createdBy: by }).returning({ id: leakSource.id });
  return { id: row.id, key: salt ? ingestKey(serverSecret(), row.id, salt) : null };
}

export async function updateSource(id: number, f: Record<string, unknown>): Promise<void> {
  const set: Partial<typeof leakSource.$inferInsert> = {};
  if (typeof f.active === "boolean") set.active = f.active;
  if (RELIABILITY.includes(f.reliability as Reliability)) set.reliability = f.reliability as string;
  if (typeof f.name === "string" && f.name.trim()) set.name = f.name.trim().slice(0, 80);
  if (!Object.keys(set).length) throw new LeakError("Rien à modifier.");
  await getDb().update(leakSource).set(set).where(eq(leakSource.id, id));
}

/** Nouvelle clé : l'ancienne cesse immédiatement de fonctionner. */
export async function rotateKey(id: number): Promise<string> {
  const salt = newSalt();
  const res = await getDb().update(leakSource).set({ keySalt: salt }).where(and(eq(leakSource.id, id), ne(leakSource.kind, "manual"))).returning({ id: leakSource.id });
  if (!res.length) throw new LeakError("Source introuvable.", 404);
  return ingestKey(serverSecret(), id, salt);
}

/** Source technique (MISP, TAXII, saisie analyste), créée à la première utilisation. */
export async function systemSource(kind: "misp" | "taxii" | "manual", name: string, reliability = "C"): Promise<number> {
  const db = getDb();
  const [found] = await db.select({ id: leakSource.id }).from(leakSource).where(and(eq(leakSource.kind, kind), eq(leakSource.name, name)));
  if (found) return found.id;
  const [row] = await db.insert(leakSource).values({ name, kind, reliability, createdBy: "système" }).returning({ id: leakSource.id });
  return row.id;
}

// ---------- Ingestion ----------

const RATE_PER_MIN = () => Number(process.env.LEAK_RATE_PER_MIN || 60);

/** Authentifie un envoi : clé de la source (Bearer) + signature HMAC du corps + fenêtre de 5 minutes + débit. */
export async function authenticateIngest(headers: Headers, body: string): Promise<{ id: number; name: string }> {
  const auth = headers.get("authorization") ?? "";
  const key = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const parsed = parseIngestKey(key);
  if (!parsed) throw new LeakError("Clé d’ingestion absente ou mal formée.", 401);
  const [src] = await getDb().select().from(leakSource).where(eq(leakSource.id, parsed.id));
  if (!src || !src.active || !keyMatches(serverSecret(), key, src.keySalt)) throw new LeakError("Clé d’ingestion invalide ou révoquée.", 401);
  const bad = verifySignature(key, headers.get("x-vq-timestamp"), body, headers.get("x-vq-signature"));
  if (bad) throw new LeakError(bad, 401);
  const [{ n }] = await getDb()
    .select({ n: sql<number>`count(*)::int` })
    .from(ingestJob)
    .where(and(eq(ingestJob.sourceId, src.id), gt(ingestJob.createdAt, new Date(Date.now() - 60_000))));
  if (n >= RATE_PER_MIN()) throw new LeakError(`Débit limité à ${RATE_PER_MIN()} envois par minute et par source.`, 429);
  return { id: src.id, name: src.name };
}

/** Valide, minimise et met en file. La charge stockée ne contient plus aucun identifiant en clair. */
export async function enqueue(sourceId: number, idempotencyKey: string, body: unknown): Promise<{ jobId: number; duplicate: boolean; accepted: number; rejected: string[] }> {
  const { events, rejected } = parseIncoming(body, sourceId, pepper());
  if (!events.length) throw new LeakError(rejected.join(" ; ") || "Aucun événement valide.", 422);
  const key = idempotencyKey.slice(0, 200) || createHash("sha256").update(JSON.stringify(events)).digest("hex");
  const db = getDb();
  const [row] = await db
    .insert(ingestJob)
    .values({ sourceId, idempotencyKey: key, payload: { events } as unknown as Record<string, unknown> })
    .onConflictDoNothing()
    .returning({ id: ingestJob.id });
  await db.update(leakSource).set({ lastIngestAt: new Date() }).where(eq(leakSource.id, sourceId));
  if (row) return { jobId: row.id, duplicate: false, accepted: events.length, rejected };
  const [prev] = await db.select({ id: ingestJob.id }).from(ingestJob).where(and(eq(ingestJob.sourceId, sourceId), eq(ingestJob.idempotencyKey, key)));
  return { jobId: prev.id, duplicate: true, accepted: 0, rejected };
}

async function upsertEvent(sourceId: number, e: MinEvent): Promise<number> {
  const db = getDb();
  const now = new Date();
  const [ev] = await db
    .insert(leakEvent)
    .values({
      sourceId,
      externalId: e.externalId,
      evidenceHash: e.evidenceHash,
      title: e.title,
      actor: e.actor,
      victim: e.victim,
      victimDomain: e.victimDomain,
      postedAt: e.postedAt ? new Date(e.postedAt) : null,
      volume: e.volume,
      dataClasses: e.dataClasses,
      price: e.price,
      reference: e.reference,
    })
    .onConflictDoUpdate({
      target: leakEvent.evidenceHash,
      set: {
        updatedAt: now,
        observedAt: now,
        volume: sql`greatest(${leakEvent.volume}, excluded.volume)`,
        dataClasses: sql`(select coalesce(jsonb_agg(distinct x order by x), '[]'::jsonb) from jsonb_array_elements_text(${leakEvent.dataClasses} || excluded.data_classes) as x)`,
        victimDomain: sql`coalesce(${leakEvent.victimDomain}, excluded.victim_domain)`,
        actor: sql`case when ${leakEvent.actor} = '' then excluded.actor else ${leakEvent.actor} end`,
        reference: sql`case when ${leakEvent.reference} = '' then excluded.reference else ${leakEvent.reference} end`,
      },
    })
    .returning({ id: leakEvent.id });
  for (let i = 0; i < e.indicators.length; i += 500) {
    await db
      .insert(leakIndicator)
      .values(e.indicators.slice(i, i + 500).map((x) => ({ eventId: ev.id, ...x })))
      .onConflictDoUpdate({
        target: [leakIndicator.eventId, leakIndicator.valueHash],
        set: {
          lastSeen: now,
          hasPassword: sql`${leakIndicator.hasPassword} or excluded.has_password`,
          hasCookie: sql`${leakIndicator.hasCookie} or excluded.has_cookie`,
          hasPii: sql`${leakIndicator.hasPii} or excluded.has_pii`,
        },
      });
  }
  return ev.id;
}

/** Traite la file (envois, connecteurs, saisies) : création des événements, corrélation, alertes. */
export async function processQueue(limit = 20): Promise<{ jobs: number; events: number; alerts: number; failed: number }> {
  if (!dbConfigured()) return { jobs: 0, events: 0, alerts: 0, failed: 0 };
  const db = getDb();
  // Tâches bloquées (fonction interrompue) : remises en file au bout de 10 minutes
  await db
    .update(ingestJob)
    .set({ status: "queued" })
    .where(and(eq(ingestJob.status, "processing"), lt(ingestJob.processedAt, new Date(Date.now() - 600_000))));
  const claimed = await db
    .update(ingestJob)
    .set({ status: "processing", attempts: sql`${ingestJob.attempts} + 1`, processedAt: new Date() })
    .where(
      inArray(
        ingestJob.id,
        db
          .select({ id: ingestJob.id })
          .from(ingestJob)
          .where(or(eq(ingestJob.status, "queued"), and(eq(ingestJob.status, "error"), lt(ingestJob.attempts, 3))))
          .orderBy(ingestJob.createdAt)
          .limit(limit),
      ),
    )
    .returning();
  let events = 0;
  let alerts = 0;
  let failed = 0;
  for (const job of claimed) {
    try {
      const list = ((job.payload as { events?: MinEvent[] } | null)?.events ?? []) as MinEvent[];
      const ids: number[] = [];
      for (const e of list) ids.push(await upsertEvent(job.sourceId, e));
      for (const id of new Set(ids)) alerts += await correlate(id);
      events += ids.length;
      // Charge vidée une fois traitée (minimisation) ; seul le compte rendu reste.
      await db.update(ingestJob).set({ status: "done", payload: null, error: null, result: { events: ids.length }, processedAt: new Date() }).where(eq(ingestJob.id, job.id));
    } catch (e) {
      failed++;
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`[fuites] tâche ${job.id} : ${msg}`);
      await db.update(ingestJob).set({ status: "error", error: msg.slice(0, 500) }).where(eq(ingestJob.id, job.id));
    }
  }
  return { jobs: claimed.length, events, alerts, failed };
}

/** Saisie manuelle par un analyste : même chaîne que l'API (minimisation, file, corrélation). */
export async function manualEntry(body: unknown, by: string): Promise<{ events: number; alerts: number; rejected: string[] }> {
  const src = await systemSource("manual", "Saisie analyste", "C");
  const q = await enqueue(src, `manuel:${by}:${Date.now()}`, body);
  const r = await processQueue(5);
  return { events: q.accepted, alerts: r.alerts, rejected: q.rejected };
}

// ---------- Corrélation ----------

const sameOrSub = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);
const RANK: Record<string, number> = { account: 5, domain: 4, subdomain: 3, typosquat: 2, brand: 1 };

/**
 * Rapproche un événement des listes de surveillance : domaines vérifiés (identifiants du domaine ou de ses
 * sous-domaines, comptes déclarés, domaines ressemblants) et marques (titre ou victime). Met à jour les
 * correspondances, les scores et les alertes. Renvoie le nombre de nouvelles alertes.
 */
export async function correlate(eventId: number): Promise<number> {
  const db = getDb();
  const [row] = await db.select({ e: leakEvent, s: leakSource }).from(leakEvent).innerJoin(leakSource, eq(leakSource.id, leakEvent.sourceId)).where(eq(leakEvent.id, eventId));
  if (!row) return 0;
  const { e, s } = row;
  if (e.status === "false_positive") {
    await db.delete(leakMatch).where(eq(leakMatch.eventId, eventId));
    await db.delete(ctiAlert).where(and(eq(ctiAlert.source, "darkweb"), sql`${ctiAlert.externalId} like ${`leak:${eventId}:%`}`));
    return 0;
  }
  const inds = await db
    .select({ domain: leakIndicator.domain, valueHash: leakIndicator.valueHash, kind: leakIndicator.kind, hasPassword: leakIndicator.hasPassword, hasCookie: leakIndicator.hasCookie, hasPii: leakIndicator.hasPii })
    .from(leakIndicator)
    .where(eq(leakIndicator.eventId, eventId));
  const hosts = new Set([...inds.map((i) => i.domain).filter((d): d is string => Boolean(d)), ...(e.victimDomain ? [e.victimDomain] : [])]);
  const watches = await db
    .select()
    .from(watchItem)
    .where(or(and(eq(watchItem.kind, "domain"), isNotNull(watchItem.verifiedAt)), eq(watchItem.kind, "brand")));

  type Hit = { userId: string; watchId: number; watchValue: string; mode: string; count: number; flags: { password: boolean; cookie: boolean; pii: boolean } };
  const hits: Hit[] = [];
  const pep = pepper();
  for (const w of watches) {
    if (w.kind === "brand") {
      if (containsTerm(`${e.title} ${e.victim}`, w.value)) hits.push({ userId: w.userId, watchId: w.id, watchValue: w.value, mode: "brand", count: 0, flags: { password: false, cookie: false, pii: false } });
      continue;
    }
    const mine = inds.filter((i) => i.domain && sameOrSub(i.domain, w.value));
    const victimHit = Boolean(e.victimDomain && sameOrSub(e.victimDomain, w.value));
    if (mine.length || victimHit) {
      const accounts = await db.select({ email: watchAccount.email }).from(watchAccount).where(and(eq(watchAccount.userId, w.userId), eq(watchAccount.domain, w.value)));
      const declared = new Set(accounts.map((a) => keyedHash(pep, "email", a.email)));
      const acc = mine.filter((i) => declared.has(i.valueHash)).length;
      const onlySub = mine.length > 0 && mine.every((i) => i.domain !== w.value) && !(e.victimDomain === w.value);
      hits.push({
        userId: w.userId,
        watchId: w.id,
        watchValue: w.value,
        mode: acc ? "account" : onlySub ? "subdomain" : "domain",
        count: mine.length || (e.volume ?? 0),
        flags: { password: mine.some((i) => i.hasPassword), cookie: mine.some((i) => i.hasCookie), pii: mine.some((i) => i.hasPii) },
      });
      continue;
    }
    if ([...hosts].some((h) => isLookalike(h, w.value))) hits.push({ userId: w.userId, watchId: w.id, watchValue: w.value, mode: "typosquat", count: 0, flags: { password: false, cookie: false, pii: false } });
  }

  const reliability = e.reliability ?? s.reliability;
  const date = e.postedAt ?? e.observedAt;
  const now = new Date();
  const scored = hits.map((h) => ({ ...h, score: leakScore({ reliability, date, classes: e.dataClasses, flags: h.flags, count: h.count, status: e.status, mode: h.mode }) }));

  // Correspondances : on remplace celles de l'événement par l'état courant
  await db.delete(leakMatch).where(
    and(
      eq(leakMatch.eventId, eventId),
      scored.length ? sql`(${leakMatch.userId}, ${leakMatch.watchItemId}) not in (${sql.join(scored.map((h) => sql`(${h.userId}, ${h.watchId})`), sql`, `)})` : sql`true`,
    ),
  );
  for (const h of scored) {
    await db
      .insert(leakMatch)
      .values({ userId: h.userId, watchItemId: h.watchId, eventId, mode: h.mode, indicatorCount: h.count, score: h.score })
      .onConflictDoUpdate({ target: [leakMatch.userId, leakMatch.watchItemId, leakMatch.eventId], set: { mode: h.mode, indicatorCount: h.count, score: h.score, updatedAt: now } });
  }

  // Alertes : une par utilisateur et par étape (signalement, puis confirmation), la correspondance la plus grave
  const stage = e.status === "confirmed" ? "confirmed" : "signal";
  const best = new Map<string, (typeof scored)[number]>();
  for (const h of scored) {
    const b = best.get(h.userId);
    if (!b || RANK[h.mode] > RANK[b.mode] || (RANK[h.mode] === RANK[b.mode] && h.score > b.score)) best.set(h.userId, h);
  }
  let created = 0;
  const stageFr = e.status === "confirmed" ? "confirmée" : e.status === "sample_verified" ? "vérifiée sur échantillon" : "revendiquée";
  for (const [userId, h] of best) {
    const title =
      h.mode === "account"
        ? `Comptes de ${h.watchValue} dans une fuite ${stageFr} : « ${e.title} »`
        : h.mode === "domain" || h.mode === "subdomain"
          ? `Fuite ${stageFr} visant ${h.watchValue} : « ${e.title} »`
          : h.mode === "typosquat"
            ? `Domaine ressemblant à ${h.watchValue} cité dans une fuite : « ${e.title} »`
            : `Marque « ${h.watchValue} » citée dans une fuite : « ${e.title} »`;
    const draft: AlertDraft = {
      source: "darkweb",
      externalId: `leak:${eventId}:${stage}`,
      watchValue: h.watchValue,
      severity: severityOf(h.score),
      title,
      detail: { eventId, score: h.score, mode: h.mode, status: e.status, statusFr: STATUS_FR[e.status as LeakStatus], source: s.name, reliability, dataClasses: e.dataClasses, count: h.count, actor: e.actor, postedAt: (e.postedAt ?? e.observedAt).toISOString() },
      url: `/?vue=veille#fuite-${eventId}`,
    };
    created += await saveDrafts(userId, [draft]);
  }
  return created;
}

// ---------- Restitution (utilisateur) ----------

export interface UserLeak {
  eventId: number;
  title: string;
  actor: string;
  victim: string;
  source: string;
  sourceKind: string;
  reliability: string;
  status: string;
  postedAt: string | null;
  observedAt: string;
  volume: number | null;
  dataClasses: string[];
  price: string;
  matches: { watchValue: string; mode: string; score: number; count: number }[];
  score: number;
  /** Identifiants de vos domaines : masqués, sauf les comptes que vous avez déclarés */
  accounts: { label: string; declared: boolean; kind: string; password: boolean; cookie: boolean; pii: boolean }[];
  accountsTotal: number;
}

export async function listUserLeaks(userId: string): Promise<UserLeak[]> {
  const db = getDb();
  const rows = await db
    .select({ m: leakMatch, e: leakEvent, s: leakSource, w: watchItem })
    .from(leakMatch)
    .innerJoin(leakEvent, eq(leakEvent.id, leakMatch.eventId))
    .innerJoin(leakSource, eq(leakSource.id, leakEvent.sourceId))
    .innerJoin(watchItem, eq(watchItem.id, leakMatch.watchItemId))
    .where(and(eq(leakMatch.userId, userId), ne(leakEvent.status, "false_positive")))
    .orderBy(desc(leakMatch.score), desc(leakEvent.observedAt))
    .limit(300);
  const by = new Map<number, UserLeak>();
  const domainsOf = new Map<number, string[]>();
  for (const { m, e, s, w } of rows) {
    const cur =
      by.get(e.id) ??
      ({
        eventId: e.id,
        title: e.title,
        actor: e.actor,
        victim: e.victim,
        source: s.name,
        sourceKind: s.kind,
        reliability: e.reliability ?? s.reliability,
        status: e.status,
        postedAt: e.postedAt?.toISOString() ?? null,
        observedAt: e.observedAt.toISOString(),
        volume: e.volume,
        dataClasses: e.dataClasses,
        price: e.price,
        matches: [],
        score: 0,
        accounts: [],
        accountsTotal: 0,
      } satisfies UserLeak);
    cur.matches.push({ watchValue: w.value, mode: m.mode, score: m.score, count: m.indicatorCount });
    cur.score = Math.max(cur.score, m.score);
    by.set(e.id, cur);
    if (["account", "domain", "subdomain"].includes(m.mode)) domainsOf.set(e.id, [...(domainsOf.get(e.id) ?? []), w.value]);
  }
  if (domainsOf.size) {
    const pep = pepper();
    const declared = await db.select({ email: watchAccount.email }).from(watchAccount).where(eq(watchAccount.userId, userId));
    const clear = new Map(declared.map((a) => [keyedHash(pep, "email", a.email), a.email]));
    for (const [eventId, domains] of domainsOf) {
      const cond = or(...domains.flatMap((d) => [eq(leakIndicator.domain, d), sql`${leakIndicator.domain} like ${`%.${d}`}`]));
      const inds = await db.select().from(leakIndicator).where(and(eq(leakIndicator.eventId, eventId), cond)).limit(500);
      const leak = by.get(eventId)!;
      leak.accountsTotal = inds.length;
      leak.accounts = inds
        .map((i) => ({ label: clear.get(i.valueHash) ?? i.masked, declared: clear.has(i.valueHash), kind: i.kind, password: i.hasPassword, cookie: i.hasCookie, pii: i.hasPii }))
        .sort((a, b) => Number(b.declared) - Number(a.declared) || Number(b.password || b.cookie) - Number(a.password || a.cookie) || a.label.localeCompare(b.label))
        .slice(0, 200);
    }
  }
  return [...by.values()].sort((a, b) => b.score - a.score || b.observedAt.localeCompare(a.observedAt));
}

// ---------- Qualification (analystes) ----------

export interface AnalystLeak {
  id: number;
  title: string;
  actor: string;
  victim: string;
  victimDomain: string | null;
  source: string;
  sourceKind: string;
  sourceReliability: string;
  reliability: string | null;
  status: string;
  postedAt: string | null;
  observedAt: string;
  volume: number | null;
  dataClasses: string[];
  price: string;
  reference: string;
  analystNote: string;
  qualifiedBy: string | null;
  qualifiedAt: string | null;
  indicators: number;
  withSecrets: number;
  matches: number;
}

export async function listForAnalyst(status: string | null, q = ""): Promise<AnalystLeak[]> {
  const db = getDb();
  const conds = [status && STATUSES.includes(status as LeakStatus) ? eq(leakEvent.status, status) : undefined, q ? sql`(${leakEvent.title} ilike ${`%${q}%`} or ${leakEvent.victim} ilike ${`%${q}%`} or ${leakEvent.actor} ilike ${`%${q}%`})` : undefined].filter(Boolean);
  const rows = await db
    .select({
      e: leakEvent,
      s: leakSource,
      indicators: sql<number>`(select count(*)::int from ${leakIndicator} where ${leakIndicator.eventId} = ${leakEvent.id})`,
      withSecrets: sql<number>`(select count(*)::int from ${leakIndicator} where ${leakIndicator.eventId} = ${leakEvent.id} and (${leakIndicator.hasPassword} or ${leakIndicator.hasCookie}))`,
      matches: sql<number>`(select count(*)::int from ${leakMatch} where ${leakMatch.eventId} = ${leakEvent.id})`,
    })
    .from(leakEvent)
    .innerJoin(leakSource, eq(leakSource.id, leakEvent.sourceId))
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(desc(leakEvent.observedAt))
    .limit(200);
  return rows.map(({ e, s, indicators, withSecrets, matches }) => ({
    id: e.id,
    title: e.title,
    actor: e.actor,
    victim: e.victim,
    victimDomain: e.victimDomain,
    source: s.name,
    sourceKind: s.kind,
    sourceReliability: s.reliability,
    reliability: e.reliability,
    status: e.status,
    postedAt: e.postedAt?.toISOString() ?? null,
    observedAt: e.observedAt.toISOString(),
    volume: e.volume,
    dataClasses: e.dataClasses,
    price: e.price,
    reference: e.reference,
    analystNote: e.analystNote,
    qualifiedBy: e.qualifiedBy,
    qualifiedAt: e.qualifiedAt?.toISOString() ?? null,
    indicators,
    withSecrets,
    matches,
  }));
}

/** Qualifie un événement (statut, fiabilité retenue, note) puis recalcule scores et alertes. */
export async function qualify(id: number, f: { status?: unknown; reliability?: unknown; note?: unknown }, by: string): Promise<number> {
  const set: Partial<typeof leakEvent.$inferInsert> = { qualifiedBy: by, qualifiedAt: new Date(), updatedAt: new Date() };
  if (f.status !== undefined) {
    if (!STATUSES.includes(f.status as LeakStatus)) throw new LeakError("Statut inconnu.");
    set.status = f.status as string;
  }
  if (f.reliability !== undefined) set.reliability = f.reliability === null || f.reliability === "" ? null : RELIABILITY.includes(f.reliability as Reliability) ? (f.reliability as string) : undefined;
  if (typeof f.note === "string") set.analystNote = f.note.slice(0, 2000);
  const res = await getDb().update(leakEvent).set(set).where(eq(leakEvent.id, id)).returning({ id: leakEvent.id });
  if (!res.length) throw new LeakError("Événement introuvable.", 404);
  return correlate(id);
}

// ---------- Corrélation de rattrapage et purge ----------

/** Après l'ajout ou la vérification d'un domaine : rapproche les événements récents (90 jours). */
export async function recorrelateRecent(days = 90, limit = 500): Promise<number> {
  const ids = await getDb()
    .select({ id: leakEvent.id })
    .from(leakEvent)
    .where(and(gt(leakEvent.observedAt, new Date(Date.now() - days * 86_400_000)), ne(leakEvent.status, "false_positive")))
    .orderBy(desc(leakEvent.observedAt))
    .limit(limit);
  let n = 0;
  for (const { id } of ids) n += await correlate(id);
  return n;
}

/** Conservation limitée : événements (et leurs identifiants) au-delà de LEAK_RETENTION_DAYS, file traitée au-delà de 7 jours. */
export async function purge(): Promise<{ events: number; jobs: number }> {
  if (!dbConfigured()) return { events: 0, jobs: 0 };
  const days = Number(process.env.LEAK_RETENTION_DAYS || 365);
  const db = getDb();
  const ev = await db.delete(leakEvent).where(lt(leakEvent.observedAt, new Date(Date.now() - days * 86_400_000))).returning({ id: leakEvent.id });
  const jobs = await db
    .delete(ingestJob)
    .where(and(inArray(ingestJob.status, ["done", "error"]), lt(ingestJob.createdAt, new Date(Date.now() - 7 * 86_400_000))))
    .returning({ id: ingestJob.id });
  return { events: ev.length, jobs: jobs.length };
}

export async function statusCounts(): Promise<Record<string, number>> {
  const rows = await getDb().select({ s: leakEvent.status, n: sql<number>`count(*)::int` }).from(leakEvent).groupBy(leakEvent.status);
  return Object.fromEntries(rows.map((r) => [r.s, r.n]));
}

export async function queueStats(): Promise<Record<string, number>> {
  const rows = await getDb().select({ s: ingestJob.status, n: sql<number>`count(*)::int` }).from(ingestJob).groupBy(ingestJob.status);
  return Object.fromEntries(rows.map((r) => [r.s, r.n]));
}

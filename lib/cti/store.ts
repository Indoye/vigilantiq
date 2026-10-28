/** Liste de surveillance, analyses et alertes de renseignement (base + caches partagés). */
import { and, asc, desc, eq, inArray, isNull, sql } from "drizzle-orm";
import { unstable_cache } from "next/cache.js";
import { dbConfigured, getDb } from "@/db";
import { ctiAlert, user, watchItem } from "@/db/schema";
import { draftEmail, draftInfostealer, draftLookalikes, matchBreaches, matchPhishing, matchRansom, type AlertDraft, type WatchKind, type WatchTarget } from "./match.ts";
import {
  fetchBreaches,
  fetchEmailBreaches,
  fetchInfostealer,
  fetchIocs,
  fetchRansomVictims,
  normalizeBrand,
  normalizeDomain,
  type Breach,
  type InfostealerStats,
} from "./sources.ts";
import { findLookalikes, type Lookalike } from "./typosquat.ts";

export const MAX_WATCH = Number(process.env.CTI_MAX_WATCH || 10);

// ---------- Données partagées, en cache ----------

export const getRansomVictims = () => unstable_cache(fetchRansomVictims, ["cti-ransom-v1"], { revalidate: 3600, tags: ["cti"] })();
/** Catalogue complet (pour la correspondance par domaine) ; l'onglet n'affiche que les plus récentes. */
export const getBreaches = () => unstable_cache(fetchBreaches, ["cti-breaches-v1"], { revalidate: 6 * 3600, tags: ["cti"] })();
export const getIocs = () => unstable_cache(fetchIocs, ["cti-iocs-v1"], { revalidate: 3600, tags: ["cti"] })();
export const getInfostealer = (domain: string) =>
  unstable_cache(() => fetchInfostealer(domain), ["cti-infostealer-v1", domain], { revalidate: 12 * 3600, tags: ["cti"] })();
export const getLookalikes = (domain: string) =>
  unstable_cache(() => findLookalikes(domain), ["cti-lookalikes-v1", domain], { revalidate: 12 * 3600, tags: ["cti"] })();
export const getEmailBreaches = (email: string) =>
  unstable_cache(() => fetchEmailBreaches(email), ["cti-email-v1", email.toLowerCase()], { revalidate: 12 * 3600, tags: ["cti"] })();

// ---------- Liste de surveillance ----------

export interface WatchRow {
  id: number;
  kind: WatchKind;
  value: string;
  createdAt: string;
  lastScanAt: string | null;
}

const toWatch = (r: typeof watchItem.$inferSelect): WatchRow => ({
  id: r.id,
  kind: r.kind as WatchKind,
  value: r.value,
  createdAt: r.createdAt.toISOString(),
  lastScanAt: r.lastScanAt?.toISOString() ?? null,
});

export async function listWatch(userId: string): Promise<WatchRow[]> {
  const rows = await getDb().select().from(watchItem).where(eq(watchItem.userId, userId)).orderBy(asc(watchItem.createdAt));
  return rows.map(toWatch);
}

export class WatchError extends Error {}

export async function addWatch(userId: string, kind: string, raw: string): Promise<WatchRow> {
  if (kind !== "domain" && kind !== "brand") throw new WatchError("Type inconnu : domaine ou marque.");
  const value = kind === "domain" ? normalizeDomain(raw) : normalizeBrand(raw);
  if (!value) throw new WatchError(kind === "domain" ? "Nom de domaine invalide (exemple : entreprise.sn)." : "Marque invalide : 3 à 40 caractères.");
  const db = getDb();
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(watchItem).where(eq(watchItem.userId, userId));
  if (n >= MAX_WATCH) throw new WatchError(`Limite de ${MAX_WATCH} éléments surveillés atteinte.`);
  const [row] = await db.insert(watchItem).values({ userId, kind, value }).onConflictDoNothing().returning();
  if (!row) throw new WatchError("Cet élément est déjà surveillé.");
  return toWatch(row);
}

export async function removeWatch(userId: string, id: number): Promise<boolean> {
  const res = await getDb().delete(watchItem).where(and(eq(watchItem.userId, userId), eq(watchItem.id, id))).returning({ id: watchItem.id });
  return res.length > 0;
}

// ---------- Alertes ----------

export interface AlertRow {
  id: number;
  source: string;
  severity: string;
  title: string;
  watchValue: string;
  detail: Record<string, unknown>;
  url: string;
  createdAt: string;
  seen: boolean;
}

export async function listAlerts(userId: string, limit = 300): Promise<AlertRow[]> {
  const rows = await getDb().select().from(ctiAlert).where(eq(ctiAlert.userId, userId)).orderBy(desc(ctiAlert.createdAt)).limit(limit);
  return rows.map((r) => ({
    id: r.id,
    source: r.source,
    severity: r.severity,
    title: r.title,
    watchValue: r.watchValue,
    detail: r.detail,
    url: r.url,
    createdAt: r.createdAt.toISOString(),
    seen: Boolean(r.seenAt),
  }));
}

export async function markSeen(userId: string, ids: number[] | "all"): Promise<void> {
  const where = ids === "all" ? and(eq(ctiAlert.userId, userId), isNull(ctiAlert.seenAt)) : and(eq(ctiAlert.userId, userId), inArray(ctiAlert.id, ids));
  await getDb().update(ctiAlert).set({ seenAt: new Date() }).where(where);
}

async function saveDrafts(userId: string, drafts: AlertDraft[]): Promise<number> {
  if (!drafts.length) return 0;
  const seen = new Set<string>();
  const rows = drafts
    .filter((d) => (seen.has(`${d.source}|${d.externalId}`) ? false : (seen.add(`${d.source}|${d.externalId}`), true)))
    .map((d) => ({ userId, ...d, externalId: d.externalId.slice(0, 400), title: d.title.slice(0, 300), url: d.url.slice(0, 600) }));
  let created = 0;
  for (let i = 0; i < rows.length; i += 200) {
    const res = await getDb().insert(ctiAlert).values(rows.slice(i, i + 200)).onConflictDoNothing().returning({ id: ctiAlert.id });
    created += res.length;
  }
  return created;
}

// ---------- Analyse ----------

export interface DomainReport {
  domain: string;
  infostealer: InfostealerStats | null;
  lookalikes: Lookalike[] | null;
  breaches: Breach[];
  errors: string[];
}

export interface ScanResult {
  scannedAt: string;
  created: number;
  domains: DomainReport[];
  email: { address: string; breaches: string[] | null } | null;
  errors: string[];
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Analyse complète de la liste d'un utilisateur ; enregistre les nouvelles alertes (dédoublonnées). */
export async function scanUser(userId: string, email: string | null, opts: { typosquat?: boolean } = {}): Promise<ScanResult> {
  const items = await listWatch(userId);
  const targets: WatchTarget[] = items.map((i) => ({ kind: i.kind, value: i.value }));
  const errors: string[] = [];
  const drafts: AlertDraft[] = [];

  const [victimsR, breachesR, iocsR] = await Promise.allSettled([getRansomVictims(), getBreaches(), getIocs()]);
  if (victimsR.status === "fulfilled") drafts.push(...matchRansom(targets, victimsR.value));
  else errors.push(`Sites de rançongiciels : ${msg(victimsR.reason)}`);
  const breaches = breachesR.status === "fulfilled" ? breachesR.value : [];
  if (breachesR.status === "fulfilled") drafts.push(...matchBreaches(targets, breaches));
  else errors.push(`Have I Been Pwned : ${msg(breachesR.reason)}`);
  if (iocsR.status === "fulfilled") drafts.push(...matchPhishing(targets, iocsR.value.items));
  else errors.push(`Flux d’hameçonnage : ${msg(iocsR.reason)}`);

  const domains: DomainReport[] = [];
  for (const t of targets.filter((x) => x.kind === "domain")) {
    const rep: DomainReport = { domain: t.value, infostealer: null, lookalikes: null, breaches: breaches.filter((b) => b.domain === t.value), errors: [] };
    const [isR, laR] = await Promise.allSettled([getInfostealer(t.value), opts.typosquat === false ? Promise.resolve(null) : getLookalikes(t.value)]);
    if (isR.status === "fulfilled") {
      rep.infostealer = isR.value;
      drafts.push(...draftInfostealer(isR.value));
    } else rep.errors.push(`Infostealers : ${msg(isR.reason)}`);
    if (laR.status === "fulfilled") {
      rep.lookalikes = laR.value;
      if (laR.value) drafts.push(...draftLookalikes(t.value, laR.value));
    } else rep.errors.push(`Domaines ressemblants : ${msg(laR.reason)}`);
    domains.push(rep);
  }

  let emailRes: ScanResult["email"] = null;
  if (email) {
    try {
      const list = await getEmailBreaches(email);
      emailRes = { address: email, breaches: list };
      drafts.push(...draftEmail(email, list));
    } catch (e) {
      emailRes = { address: email, breaches: null };
      errors.push(`Adresse e-mail : ${msg(e)}`);
    }
  }

  const created = await saveDrafts(userId, drafts);
  if (items.length) await getDb().update(watchItem).set({ lastScanAt: new Date() }).where(eq(watchItem.userId, userId));
  return { scannedAt: new Date().toISOString(), created, domains, email: emailRes, errors };
}

/** Passe quotidienne : analyse de tous les utilisateurs qui surveillent quelque chose, puis alertes à notifier. */
export async function scanAllUsers(): Promise<{ users: number; created: number; failed: number }> {
  if (!dbConfigured()) return { users: 0, created: 0, failed: 0 };
  const db = getDb();
  const owners = await db.selectDistinct({ id: watchItem.userId, email: user.email, verified: user.emailVerified }).from(watchItem).innerJoin(user, eq(user.id, watchItem.userId));
  let created = 0;
  let failed = 0;
  for (const o of owners) {
    try {
      // Adresse vérifiée uniquement : on ne recherche jamais dans les fuites une adresse non prouvée.
      created += (await scanUser(o.id, o.verified ? o.email : null)).created;
    } catch (e) {
      failed++;
      console.error(`[renseignement] analyse ${o.id} : ${msg(e)}`);
    }
  }
  return { users: owners.length, created, failed };
}

/** Alertes jamais notifiées, regroupées par utilisateur (pour l'e-mail quotidien). */
export async function pendingNotifications(): Promise<{ userId: string; email: string; name: string; alerts: AlertRow[] }[]> {
  if (!dbConfigured()) return [];
  const db = getDb();
  const rows = await db
    .select({ a: ctiAlert, email: user.email, name: user.name })
    .from(ctiAlert)
    .innerJoin(user, eq(user.id, ctiAlert.userId))
    .where(isNull(ctiAlert.notifiedAt))
    .orderBy(desc(ctiAlert.createdAt))
    .limit(2000);
  const by = new Map<string, { userId: string; email: string; name: string; alerts: AlertRow[] }>();
  for (const r of rows) {
    const g = by.get(r.a.userId) ?? { userId: r.a.userId, email: r.email, name: r.name, alerts: [] };
    g.alerts.push({ id: r.a.id, source: r.a.source, severity: r.a.severity, title: r.a.title, watchValue: r.a.watchValue, detail: r.a.detail, url: r.a.url, createdAt: r.a.createdAt.toISOString(), seen: Boolean(r.a.seenAt) });
    by.set(r.a.userId, g);
  }
  return [...by.values()];
}

export async function markNotified(ids: number[]): Promise<void> {
  if (!ids.length) return;
  await getDb().update(ctiAlert).set({ notifiedAt: new Date() }).where(inArray(ctiAlert.id, ids));
}

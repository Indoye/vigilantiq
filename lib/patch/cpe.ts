/**
 * Parc & correctifs — correspondance automatique entre un logiciel installé et un produit CPE de la NVD,
 * pour retrouver ses CVE même s'il n'est pas dans le catalogue suivi.
 *
 * - Le nom affiché (« Programmes et fonctionnalités ») est normalisé (sans version, architecture, édition…).
 * - Le dictionnaire CPE de la NVD est interrogé par mots-clés ; chaque produit candidat reçoit un score
 *   (titre CPE ≈ nom du logiciel, éditeur cohérent). En dessous du seuil, rien n'est associé.
 * - Les résultats (y compris « aucun ») sont mis en cache 30 jours, communs à toute la plateforme ;
 *   une organisation peut corriger ou ignorer une correspondance pour elle seule.
 * Les fonctions pures sont exportées pour les tests.
 */
import { and, eq, inArray, or, sql } from "drizzle-orm";
import { getDb } from "@/db";
import { patchComponent, patchCpeMap, patchDevice } from "@/db/schema";
import { matchApp } from "./catalog.ts";
import { bestCandidate, normalizeName, tokens, type CpeCandidate } from "./cpematch.ts";

export { bestCandidate, normalizeName, MIN_CONFIDENCE } from "./cpematch.ts";

import { MIN_CONFIDENCE } from "./cpematch.ts";
const TTL = 30 * 86_400_000;
const CPE_URL = () => process.env.NVD_CPE_API_URL || "https://services.nvd.nist.gov/rest/json/cpes/2.0";
const UA = "vigilantiq-parc/1.0 (+https://vercel.com)";

/** Recherche dans le dictionnaire CPE (applications uniquement, entrées non obsolètes). */
export async function searchCpe(query: string): Promise<CpeCandidate[]> {
  const url = `${CPE_URL()}?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=200`;
  const res = await fetch(url, {
    headers: { "User-Agent": UA, ...(process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}) },
    signal: AbortSignal.timeout(30_000),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`NVD (dictionnaire CPE) a répondu ${res.status}`);
  const j = (await res.json()) as { products?: { cpe?: { cpeName?: string; deprecated?: boolean; titles?: { title: string; lang: string }[] } }[] };
  const out: CpeCandidate[] = [];
  for (const p of j.products ?? []) {
    const c = p.cpe;
    if (!c?.cpeName || c.deprecated) continue;
    const parts = c.cpeName.split(":");
    if (parts[2] !== "a" || !parts[3] || !parts[4]) continue;
    const title = c.titles?.find((t) => t.lang === "en")?.title ?? c.titles?.[0]?.title ?? `${parts[3]} ${parts[4]}`;
    out.push({ vendor: parts[3], product: parts[4], title });
  }
  return out;
}

export type CpeMap = typeof patchCpeMap.$inferSelect;

/** Correspondances utilisables pour une organisation : ses corrections d'abord, puis la base commune. */
export async function mappingsFor(orgId: string, keys: string[]): Promise<Map<string, CpeMap>> {
  if (!keys.length) return new Map();
  const rows = await getDb()
    .select()
    .from(patchCpeMap)
    .where(and(inArray(patchCpeMap.key, keys), or(eq(patchCpeMap.scope, orgId), eq(patchCpeMap.scope, "*"))));
  const out = new Map<string, CpeMap>();
  for (const r of rows) if (!out.has(r.key) || r.scope !== "*") out.set(r.key, r);
  return out;
}

/** Résout un nom (si absent ou périmé dans la base commune). */
export async function resolveOne(displayName: string, publisher: string): Promise<CpeMap | null> {
  const key = normalizeName(displayName);
  if (!key || tokens(key).length === 0) return null;
  const db = getDb();
  const [cur] = await db.select().from(patchCpeMap).where(and(eq(patchCpeMap.scope, "*"), eq(patchCpeMap.key, key)));
  if (cur && Date.now() - cur.checkedAt.getTime() < TTL) return cur;
  const cands = await searchCpe(key);
  const best = bestCandidate(displayName, publisher, cands);
  const ok = best && best.confidence >= MIN_CONFIDENCE;
  const values = {
    scope: "*",
    key,
    label: displayName.slice(0, 200),
    vendor: ok ? best.vendor : "",
    product: ok ? best.product : "",
    title: ok ? best.title : "",
    status: ok ? "auto" : "aucun",
    confidence: best?.confidence ?? 0,
    checkedAt: new Date(),
  };
  const [r] = await db
    .insert(patchCpeMap)
    .values(values)
    .onConflictDoUpdate({ target: [patchCpeMap.scope, patchCpeMap.key], set: values })
    .returning();
  return r;
}

/**
 * Résout par lots les logiciels du parc (hors catalogue) qui n'ont pas encore de correspondance.
 * Limité par le budget de temps et le débit autorisé par la NVD (5 requêtes / 30 s sans clé, 50 avec).
 */
export async function resolvePending(budgetMs: number, orgId?: string): Promise<{ resolved: number; pending: number; errors: string[] }> {
  const deadline = Date.now() + budgetMs;
  const db = getDb();
  const rows = await db
    .select({ name: patchComponent.name, vendor: sql<string>`max(${patchComponent.vendor})` })
    .from(patchComponent)
    .innerJoin(patchDevice, eq(patchDevice.id, patchComponent.deviceId))
    .where(and(eq(patchComponent.kind, "app"), orgId ? eq(patchDevice.orgId, orgId) : sql`true`))
    .groupBy(patchComponent.name)
    .limit(2000);
  const todo = new Map<string, { name: string; vendor: string }>();
  for (const r of rows) {
    if (matchApp(r.name)) continue;
    const k = normalizeName(r.name);
    if (k && tokens(k).length && !todo.has(k)) todo.set(k, r);
  }
  if (!todo.size) return { resolved: 0, pending: 0, errors: [] };
  const known = await db
    .select({ key: patchCpeMap.key, at: patchCpeMap.checkedAt })
    .from(patchCpeMap)
    .where(and(eq(patchCpeMap.scope, "*"), inArray(patchCpeMap.key, [...todo.keys()])));
  for (const k of known) if (Date.now() - k.at.getTime() < TTL) todo.delete(k.key);
  const pause = process.env.NVD_API_KEY ? 700 : 6500;
  let resolved = 0;
  const errors: string[] = [];
  for (const { name, vendor } of todo.values()) {
    if (Date.now() + pause > deadline) break;
    try {
      await resolveOne(name, vendor);
      resolved++;
    } catch (e) {
      errors.push(e instanceof Error ? e.message : String(e));
      if (errors.length >= 3) break;
    }
    await new Promise((r) => setTimeout(r, pause));
  }
  return { resolved, pending: todo.size - resolved, errors };
}

/** Correction par une organisation : produit CPE choisi, ou logiciel ignoré (aucune CVE recherchée). */
export async function setOrgMapping(orgId: string, displayName: string, m: { vendor?: string; product?: string; ignore?: boolean } | null): Promise<void> {
  const key = normalizeName(displayName);
  if (!key) throw new Error("Nom de logiciel invalide.");
  const db = getDb();
  if (!m) {
    await db.delete(patchCpeMap).where(and(eq(patchCpeMap.scope, orgId), eq(patchCpeMap.key, key)));
    return;
  }
  const clean = (s: string | undefined) => (s ?? "").trim().toLowerCase().replace(/\s+/g, "_");
  const vendor = clean(m.vendor);
  const product = clean(m.product);
  if (!m.ignore && (!/^[a-z0-9_.\-+\\!]{1,80}$/.test(vendor) || !/^[a-z0-9_.\-+\\!]{1,120}$/.test(product))) throw new Error("Éditeur et produit CPE attendus (ex. zoom / zoom).");
  const values = { scope: orgId, key, label: displayName.slice(0, 200), vendor: m.ignore ? "" : vendor, product: m.ignore ? "" : product, title: "", status: m.ignore ? "ignore" : "manuel", confidence: 100, checkedAt: new Date() };
  await db
    .insert(patchCpeMap)
    .values(values)
    .onConflictDoUpdate({ target: [patchCpeMap.scope, patchCpeMap.key], set: values });
}

/** Appareils de l'organisation qui ont ce logiciel (pour recalculer leurs vulnérabilités). */
export async function devicesWith(orgId: string, displayName: string): Promise<number[]> {
  const key = normalizeName(displayName);
  const rows = await getDb()
    .selectDistinct({ id: patchDevice.id, name: patchComponent.name })
    .from(patchComponent)
    .innerJoin(patchDevice, eq(patchDevice.id, patchComponent.deviceId))
    .where(and(eq(patchDevice.orgId, orgId), eq(patchComponent.kind, "app")));
  return [...new Set(rows.filter((r) => normalizeName(r.name) === key).map((r) => r.id))];
}


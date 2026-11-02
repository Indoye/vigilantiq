/**
 * Parc & correctifs — sources de vulnérabilités, avec cache en base partagé par tous les utilisateurs :
 * NVD 2.0 (une requête par produit CPE, toutes les CVE du produit) et OSV.dev (paquets des distributions Linux).
 * NVD_API_URL et OSV_API_URL permettent d'utiliser un miroir.
 */
import { eq, inArray } from "drizzle-orm";
import { getDb } from "@/db";
import { exploit, patchCache } from "@/db/schema";
import { fetchEpss, fetchKev } from "../sources.ts";
import { compactNvdItem, type NvdCve, type OsvQuery } from "./core.ts";

const UA = "vigilantiq-parc/1.0 (+https://vercel.com)";
const NVD_URL = () => process.env.NVD_API_URL || "https://services.nvd.nist.gov/rest/json/cves/2.0";
const OSV_URL = () => (process.env.OSV_API_URL || "https://api.osv.dev").replace(/\/+$/, "");
/** Fraîcheur du cache : produits NVD 24 h, fiches OSV 3 jours. */
const NVD_TTL = 24 * 3600_000;
const OSV_TTL = 3 * 86_400_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function cacheGet<T>(key: string): Promise<{ data: T; fetchedAt: Date } | null> {
  const [r] = await getDb().select().from(patchCache).where(eq(patchCache.key, key));
  return r ? { data: r.data as T, fetchedAt: r.fetchedAt } : null;
}
async function cachePut(key: string, data: unknown): Promise<void> {
  const now = new Date();
  await getDb().insert(patchCache).values({ key, data, fetchedAt: now }).onConflictDoUpdate({ target: patchCache.key, set: { data, fetchedAt: now } });
}

// ---------- NVD ----------

const nvdHeaders = (): Record<string, string> => ({ "User-Agent": UA, ...(process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}) });

/** Toutes les CVE d'un produit CPE (part : o = système, a = application), réduites aux critères de ce produit. */
async function downloadNvdProduct(part: "o" | "a", vendor: string, product: string): Promise<NvdCve[]> {
  const out: NvdCve[] = [];
  let startIndex = 0;
  let total = Infinity;
  // Sans clé, la NVD accepte 5 requêtes par 30 secondes ; avec une clé, 50.
  const pause = process.env.NVD_API_KEY ? 700 : 6500;
  for (let page = 0; startIndex < total && page < 15; page++) {
    if (page > 0) await sleep(pause);
    const url = `${NVD_URL()}?virtualMatchString=${encodeURIComponent(`cpe:2.3:${part}:${vendor}:${product}`)}&noRejected&resultsPerPage=2000&startIndex=${startIndex}`;
    const res = await fetch(url, { headers: nvdHeaders(), signal: AbortSignal.timeout(60_000), cache: "no-store" });
    if (!res.ok) throw new Error(`NVD a répondu ${res.status}`);
    const json = (await res.json()) as { totalResults?: number; resultsPerPage?: number; vulnerabilities?: unknown[] };
    total = json.totalResults ?? 0;
    for (const item of json.vulnerabilities ?? []) {
      const c = compactNvdItem(item, vendor, product);
      if (c) out.push(c);
    }
    startIndex += json.resultsPerPage || 2000;
  }
  return out;
}

/** CVE d'un produit, depuis le cache (24 h) ou la NVD. En cas d'échec, le cache périmé sert encore. */
export async function nvdProduct(part: "o" | "a", vendor: string, product: string): Promise<{ items: NvdCve[]; stale: boolean }> {
  const key = `nvd:${part}:${vendor}:${product}`;
  const cached = await cacheGet<NvdCve[]>(key);
  if (cached && Date.now() - cached.fetchedAt.getTime() < NVD_TTL) return { items: cached.data, stale: false };
  try {
    const items = await downloadNvdProduct(part, vendor, product);
    await cachePut(key, items);
    return { items, stale: false };
  } catch (e) {
    if (cached) return { items: cached.data, stale: true };
    throw e;
  }
}

// ---------- OSV ----------

/** Identifiants des avis OSV qui touchent chaque paquet interrogé (même ordre que les requêtes). */
export async function osvQueryBatch(queries: OsvQuery[]): Promise<string[][]> {
  const out: string[][] = [];
  for (let i = 0; i < queries.length; i += 1000) {
    const batch = queries.slice(i, i + 1000);
    const res = await fetch(`${OSV_URL()}/v1/querybatch`, {
      method: "POST",
      headers: { "User-Agent": UA, "Content-Type": "application/json" },
      body: JSON.stringify({ queries: batch }),
      signal: AbortSignal.timeout(60_000),
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`OSV a répondu ${res.status}`);
    const json = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
    for (let j = 0; j < batch.length; j++) out.push((json.results?.[j]?.vulns ?? []).map((v) => v.id));
  }
  return out;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
/** Ne garde d'un avis OSV que ce qui sert à la corrélation. */
function slimOsv(o: any) {
  return {
    id: o.id,
    aliases: o.aliases ?? [],
    upstream: o.upstream ?? [],
    severity: o.severity ?? [],
    affected: (o.affected ?? []).map((a: any) => ({
      package: { name: a.package?.name, ecosystem: a.package?.ecosystem },
      severity: a.severity ?? [],
      ranges: (a.ranges ?? []).map((r: any) => ({ type: r.type, events: r.events ?? [] })),
    })),
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

/** Fiches OSV (cache 3 jours), téléchargées 8 par 8. Une fiche introuvable est ignorée. */
export async function osvVulns(ids: string[]): Promise<Map<string, ReturnType<typeof slimOsv>>> {
  const uniq = [...new Set(ids)];
  const map = new Map<string, ReturnType<typeof slimOsv>>();
  if (!uniq.length) return map;
  const keys = uniq.map((id) => `osv:${id}`);
  const rows: { key: string; data: unknown; fetchedAt: Date }[] = [];
  for (let i = 0; i < keys.length; i += 500) rows.push(...(await getDb().select().from(patchCache).where(inArray(patchCache.key, keys.slice(i, i + 500)))));
  const fresh = new Set<string>();
  for (const r of rows) {
    map.set(r.key.slice(4), r.data as ReturnType<typeof slimOsv>);
    if (Date.now() - r.fetchedAt.getTime() < OSV_TTL) fresh.add(r.key.slice(4));
  }
  const todo = uniq.filter((id) => !fresh.has(id));
  let errors = 0;
  for (let i = 0; i < todo.length; i += 8) {
    await Promise.all(
      todo.slice(i, i + 8).map(async (id) => {
        try {
          const res = await fetch(`${OSV_URL()}/v1/vulns/${encodeURIComponent(id)}`, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(20_000), cache: "no-store" });
          if (res.status === 404) return;
          if (!res.ok) throw new Error(`OSV a répondu ${res.status}`);
          const slim = slimOsv(await res.json());
          map.set(id, slim);
          await cachePut(`osv:${id}`, slim);
        } catch {
          errors++;
        }
      }),
    );
  }
  if (errors && errors === todo.length && todo.length > 0 && map.size === 0) throw new Error("OSV indisponible");
  return map;
}

// ---------- Signaux d'exploitation ----------

export interface Signals {
  kev: Map<string, { ransomware: boolean }>;
  epss: Map<string, number>;
  pocs: Map<string, number>;
  errors: string[];
}

/** CISA KEV, FIRST EPSS et PoC repérés par la veille, pour une liste de CVE. Une source en panne n'arrête rien. */
export async function signals(cves: string[]): Promise<Signals> {
  const errors: string[] = [];
  const out: Signals = { kev: new Map(), epss: new Map(), pocs: new Map(), errors };
  const ids = [...new Set(cves)];
  if (!ids.length) return out;
  try {
    const kev = await fetchKev();
    for (const id of ids) {
      const k = kev.get(id);
      if (k) out.kev.set(id, { ransomware: k.ransomware });
    }
  } catch (e) {
    errors.push(`CISA KEV : ${e instanceof Error ? e.message : e}`);
  }
  try {
    for (const [id, v] of await fetchEpss(ids)) out.epss.set(id, v.epss);
  } catch (e) {
    errors.push(`EPSS : ${e instanceof Error ? e.message : e}`);
  }
  for (let i = 0; i < ids.length; i += 1000) {
    const rows = await getDb().select({ cveId: exploit.cveId }).from(exploit).where(inArray(exploit.cveId, ids.slice(i, i + 1000)));
    for (const r of rows) out.pocs.set(r.cveId, (out.pocs.get(r.cveId) ?? 0) + 1);
  }
  return out;
}

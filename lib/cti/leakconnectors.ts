/**
 * Connecteurs en lecture vers des plateformes de partage : MISP (REST) et TAXII 2.1.
 * Les événements récupérés suivent exactement la même chaîne que l'API d'ingestion (minimisation, file, corrélation).
 *
 * MISP  : MISP_URL, MISP_API_KEY, MISP_TAGS (facultatif, ex. « dark-web,data-leak »), MISP_RELIABILITY (A–F, défaut B)
 * TAXII : TAXII_URL (racine d'API, ex. https://taxii.exemple.org/api1/), TAXII_COLLECTION,
 *         TAXII_TOKEN ou TAXII_USER + TAXII_PASSWORD, TAXII_RELIABILITY (défaut C)
 */
import { eq } from "drizzle-orm";
import { getDb } from "@/db";
import { leakSource } from "@/db/schema";
import { mispToEvents, stixToEvents } from "./leaks.ts";
import { enqueue, systemSource } from "./leakstore.ts";

const TIMEOUT = 20_000;
const rel = (v: string | undefined, d: string) => (v && /^[A-F]$/.test(v) ? v : d);

export const mispConfigured = () => Boolean(process.env.MISP_URL && process.env.MISP_API_KEY);
export const taxiiConfigured = () => Boolean(process.env.TAXII_URL && process.env.TAXII_COLLECTION);

async function lastRun(id: number): Promise<Date | null> {
  const [s] = await getDb().select({ t: leakSource.lastIngestAt }).from(leakSource).where(eq(leakSource.id, id));
  return s?.t ?? null;
}

async function inBatches(sourceId: number, prefix: string, events: Record<string, unknown>[]): Promise<number> {
  let n = 0;
  for (let i = 0; i < events.length; i += 100) {
    const batch = events.slice(i, i + 100);
    const key = `${prefix}:${batch.map((e) => String(e.external_id ?? "")).join(",")}`.slice(0, 200);
    try {
      n += (await enqueue(sourceId, key, { events: batch })).accepted;
    } catch (e) {
      console.error(`[fuites] ${prefix} : ${e instanceof Error ? e.message : e}`);
    }
  }
  return n;
}

export async function pullMisp(): Promise<{ events: number } | { skipped: string }> {
  if (!mispConfigured()) return { skipped: "MISP non configuré" };
  const id = await systemSource("misp", "MISP", rel(process.env.MISP_RELIABILITY, "B"));
  const since = await lastRun(id);
  const tags = (process.env.MISP_TAGS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const base = process.env.MISP_URL!.replace(/\/+$/, "");
  const res = await fetch(`${base}/events/restSearch`, {
    method: "POST",
    headers: { Authorization: process.env.MISP_API_KEY!, Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      returnFormat: "json",
      limit: 200,
      published: true,
      ...(tags.length ? { tags } : {}),
      // Fenêtre : depuis la dernière collecte (au plus 7 jours), sinon 1 jour
      timestamp: since ? Math.floor(Math.max(since.getTime(), Date.now() - 7 * 86_400_000) / 1000) : "1d",
    }),
    signal: AbortSignal.timeout(TIMEOUT),
  });
  if (!res.ok) throw new Error(`MISP a répondu ${res.status}`);
  const events = mispToEvents(await res.json());
  return { events: await inBatches(id, "misp", events) };
}

export async function pullTaxii(): Promise<{ events: number } | { skipped: string }> {
  if (!taxiiConfigured()) return { skipped: "TAXII non configuré" };
  const id = await systemSource("taxii", "TAXII", rel(process.env.TAXII_RELIABILITY, "C"));
  const since = (await lastRun(id)) ?? new Date(Date.now() - 86_400_000);
  const base = process.env.TAXII_URL!.replace(/\/+$/, "");
  const headers: Record<string, string> = { Accept: "application/taxii+json;version=2.1" };
  if (process.env.TAXII_TOKEN) headers.Authorization = `Bearer ${process.env.TAXII_TOKEN}`;
  else if (process.env.TAXII_USER) headers.Authorization = `Basic ${Buffer.from(`${process.env.TAXII_USER}:${process.env.TAXII_PASSWORD ?? ""}`).toString("base64")}`;
  const objects: unknown[] = [];
  let next: string | undefined;
  for (let page = 0; page < 10; page++) {
    const u = new URL(`${base}/collections/${encodeURIComponent(process.env.TAXII_COLLECTION!)}/objects/`);
    u.searchParams.set("added_after", since.toISOString());
    u.searchParams.set("limit", "500");
    if (next) u.searchParams.set("next", next);
    const res = await fetch(u.toString(), { headers, signal: AbortSignal.timeout(TIMEOUT) });
    if (!res.ok) throw new Error(`TAXII a répondu ${res.status}`);
    const env = (await res.json()) as { objects?: unknown[]; more?: boolean; next?: string };
    objects.push(...(env.objects ?? []));
    if (!env.more || !env.next) break;
    next = env.next;
  }
  return { events: await inBatches(id, "taxii", stixToEvents(objects)) };
}

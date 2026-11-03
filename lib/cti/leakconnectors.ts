/**
 * Connecteurs en lecture vers des plateformes de partage : MISP (REST) et TAXII 2.1.
 * Les événements récupérés suivent exactement la même chaîne que l'API d'ingestion (minimisation, file, corrélation).
 *
 * Base commune de la plateforme : variables d'environnement (MISP_URL, MISP_API_KEY, MISP_TAGS, MISP_RELIABILITY ;
 * TAXII_URL, TAXII_COLLECTION, TAXII_TOKEN ou TAXII_USER + TAXII_PASSWORD, TAXII_RELIABILITY).
 * Organisations : mêmes clés, saisies dans Mon compte → Organisation (chiffrées) ; leurs événements restent privés.
 */
import { eq } from "drizzle-orm";
import { getDb } from "@/db";
import { leakSource } from "@/db/schema";
import { mispToEvents, stixToEvents } from "./leaks.ts";
import { enqueue, systemSource, type LeakScope } from "./leakstore.ts";
import { connectorsOfType, markConnectorRun } from "../orgconnectors.ts";

type Cfg = Record<string, string | undefined>;
const platformCfg = (): Cfg => process.env as Cfg;

const TIMEOUT = 20_000;
const rel = (v: string | undefined, d: string) => (v && /^[A-F]$/.test(v) ? v : d);

export const mispConfigured = (cfg: Cfg = platformCfg()) => Boolean(cfg.MISP_URL && cfg.MISP_API_KEY);
export const taxiiConfigured = (cfg: Cfg = platformCfg()) => Boolean(cfg.TAXII_URL && cfg.TAXII_COLLECTION);

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

export async function pullMisp(cfg: Cfg = platformCfg(), scope: LeakScope = null): Promise<{ events: number } | { skipped: string }> {
  if (!mispConfigured(cfg)) return { skipped: "MISP non configuré" };
  const id = await systemSource("misp", "MISP", rel(cfg.MISP_RELIABILITY, "B"), scope);
  const since = await lastRun(id);
  const tags = (cfg.MISP_TAGS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const base = cfg.MISP_URL!.replace(/\/+$/, "");
  const res = await fetch(`${base}/events/restSearch`, {
    method: "POST",
    headers: { Authorization: cfg.MISP_API_KEY!, Accept: "application/json", "Content-Type": "application/json" },
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

export async function pullTaxii(cfg: Cfg = platformCfg(), scope: LeakScope = null): Promise<{ events: number } | { skipped: string }> {
  if (!taxiiConfigured(cfg)) return { skipped: "TAXII non configuré" };
  const id = await systemSource("taxii", "TAXII", rel(cfg.TAXII_RELIABILITY, "C"), scope);
  const since = (await lastRun(id)) ?? new Date(Date.now() - 86_400_000);
  const base = cfg.TAXII_URL!.replace(/\/+$/, "");
  const headers: Record<string, string> = { Accept: "application/taxii+json;version=2.1" };
  if (cfg.TAXII_TOKEN) headers.Authorization = `Bearer ${cfg.TAXII_TOKEN}`;
  else if (cfg.TAXII_USER) headers.Authorization = `Basic ${Buffer.from(`${cfg.TAXII_USER}:${cfg.TAXII_PASSWORD ?? ""}`).toString("base64")}`;
  const objects: unknown[] = [];
  let next: string | undefined;
  for (let page = 0; page < 10; page++) {
    const u = new URL(`${base}/collections/${encodeURIComponent(cfg.TAXII_COLLECTION!)}/objects/`);
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

/** Passe quotidienne : MISP et TAXII de la plateforme, puis ceux de chaque organisation (événements privés). */
export async function pullAllLeakConnectors(): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  const run = async (f: () => Promise<unknown>) => f().catch((e) => ({ error: e instanceof Error ? e.message : String(e) }));
  out.platform = { misp: await run(() => pullMisp()), taxii: await run(() => pullTaxii()) };
  let orgs = 0;
  for (const type of ["misp", "taxii"] as const) {
    for (const c of await connectorsOfType(type)) {
      orgs++;
      const r = await run(() => (type === "misp" ? pullMisp(c.cfg, c.orgId) : pullTaxii(c.cfg, c.orgId)));
      await markConnectorRun(c.orgId, type, r && typeof r === "object" && "error" in r ? String((r as { error: unknown }).error) : null);
    }
  }
  out.organisations = orgs;
  return out;
}

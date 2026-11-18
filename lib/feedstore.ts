/**
 * Collecte continue des vulnérabilités.
 *
 * Le flux (NVD, CISA KEV, CVE.org, EPSS, flux des CERT et éditeurs) n'est plus calculé à la demande d'une page :
 * une collecte le recalcule régulièrement et en garde un instantané en base. Les pages et l'API lisent
 * le dernier instantané (lecture rapide, toujours la même donnée pour tous).
 *
 * Déclencheurs, tous protégés par le même verrou (une seule collecte à la fois, au plus une toutes les 4 min) :
 * - l'ordonnanceur externe (GitHub Actions, toutes les 10 min) qui appelle /api/feed ;
 * - chaque navigateur ouvert sur l'application, qui interroge /api/feed toutes les 3 min ;
 * - la passe quotidienne (Vercel Cron).
 */
import { gunzipSync, gzipSync } from "node:zlib";
import { desc, eq, lt, sql } from "drizzle-orm";
import { revalidatePath, revalidateTag } from "next/cache";
import { dbConfigured, getDb } from "@/db";
import { feedSnapshot, feedState } from "@/db/schema";
import { getDailyFeed } from "./feed";
import { getRssSnapshot } from "./rss";
import type { Feed } from "./types";

/** Âge à partir duquel l'instantané est recalculé (minutes). */
export const STALE_MINUTES = Number(process.env.FEED_REFRESH_MINUTES || 10);
/** Intervalle minimal entre deux collectes, quel que soit le déclencheur (minutes). */
const MIN_INTERVAL_MINUTES = 4;
/** Au-delà, une collecte « en cours » est considérée comme interrompue (minutes). */
const LOCK_MINUTES = 6;
const KEEP = 3;

export interface FeedVersion {
  generatedAt: string | null;
  total: number;
  added: string[];
  refreshing: boolean;
  lastOkAt: string | null;
  lastError: string | null;
}

const encode = (f: Feed) => gzipSync(Buffer.from(JSON.stringify(f))).toString("base64");
const decode = (s: string) => JSON.parse(gunzipSync(Buffer.from(s, "base64")).toString("utf8")) as Feed;

// Dernier instantané lu, gardé en mémoire par instance : on ne relit les données que si une collecte a eu lieu.
const g = globalThis as unknown as { __vqFeed?: { id: number; feed: Feed } };

/** Dernier instantané (null s'il n'y en a pas encore). */
export async function latestFeed(): Promise<Feed | null> {
  if (!dbConfigured()) return null;
  const db = getDb();
  const [head] = await db.select({ id: feedSnapshot.id }).from(feedSnapshot).orderBy(desc(feedSnapshot.id)).limit(1);
  if (!head) return null;
  if (g.__vqFeed?.id === head.id) return g.__vqFeed.feed;
  const [row] = await db.select({ id: feedSnapshot.id, data: feedSnapshot.data }).from(feedSnapshot).where(eq(feedSnapshot.id, head.id));
  if (!row) return null;
  const feed = decode(row.data);
  g.__vqFeed = { id: row.id, feed };
  return feed;
}

/** Version du flux (requête légère, pour les navigateurs et l'ordonnanceur). */
export async function feedVersion(): Promise<FeedVersion> {
  const db = getDb();
  const [[snap], [st]] = await Promise.all([
    db.select({ generatedAt: feedSnapshot.generatedAt, total: feedSnapshot.total, added: feedSnapshot.added }).from(feedSnapshot).orderBy(desc(feedSnapshot.id)).limit(1),
    db.select().from(feedState).where(eq(feedState.id, 1)),
  ]);
  const lockedAt = st?.refreshingSince?.getTime() ?? 0;
  return {
    generatedAt: snap?.generatedAt.toISOString() ?? null,
    total: snap?.total ?? 0,
    added: snap?.added ?? [],
    refreshing: lockedAt > Date.now() - LOCK_MINUTES * 60_000,
    lastOkAt: st?.lastOkAt?.toISOString() ?? null,
    lastError: st?.lastError ?? null,
  };
}

/** L'instantané est-il à recalculer ? */
export function isStale(v: Pick<FeedVersion, "generatedAt">): boolean {
  return !v.generatedAt || Date.now() - Date.parse(v.generatedAt) > STALE_MINUTES * 60_000;
}

/** Réserve la collecte : une seule à la fois, et pas plus d'une toutes les MIN_INTERVAL_MINUTES (sauf `force`). */
async function claim(force: boolean): Promise<boolean> {
  const rows = await getDb().execute(sql`
    insert into feed_state (id, refreshing_since) values (1, now())
    on conflict (id) do update set refreshing_since = now()
    where (feed_state.refreshing_since is null or feed_state.refreshing_since < now() - make_interval(mins => ${LOCK_MINUTES}))
      and (${force} or feed_state.last_ok_at is null or feed_state.last_ok_at < now() - make_interval(mins => ${MIN_INTERVAL_MINUTES}))
    returning id`);
  return rows.length > 0;
}

export interface RefreshResult {
  ran: boolean;
  generatedAt?: string;
  total?: number;
  added?: number;
  kept?: boolean;
  error?: string;
  ms?: number;
}

/**
 * Recalcule le flux et enregistre un nouvel instantané.
 * Si la NVD ne répond pas, l'instantané précédent est conservé plutôt que remplacé par un flux appauvri.
 */
export async function refreshFeed(opts: { force?: boolean } = {}): Promise<RefreshResult> {
  if (!dbConfigured()) return { ran: false, error: "DATABASE_URL absente" };
  if (!(await claim(Boolean(opts.force)))) return { ran: false };
  const db = getDb();
  const t0 = Date.now();
  try {
    const rss = await getRssSnapshot();
    const feed = await getDailyFeed(rss);
    const [prev] = await db.select({ id: feedSnapshot.id, data: feedSnapshot.data }).from(feedSnapshot).orderBy(desc(feedSnapshot.id)).limit(1);
    const nvdOk = feed.sources.find((s) => s.name === "NVD")?.ok !== false;
    if (prev && !nvdOk) {
      const msg = feed.errors.join(" · ") || "NVD indisponible";
      await db.update(feedState).set({ refreshingSince: null, lastError: msg, lastDurationMs: Date.now() - t0 }).where(eq(feedState.id, 1));
      console.error(`[collecte] instantané conservé : ${msg}`);
      return { ran: true, kept: true, error: msg, ms: Date.now() - t0 };
    }
    const before = new Set(prev ? (g.__vqFeed?.id === prev.id ? g.__vqFeed.feed : decode(prev.data)).vulns.map((v) => v.id) : []);
    const added = prev ? feed.vulns.filter((v) => !before.has(v.id)).map((v) => v.id) : [];
    const [row] = await db
      .insert(feedSnapshot)
      .values({ generatedAt: new Date(feed.generatedAt), total: feed.vulns.length, added: added.slice(0, 100), data: encode(feed) })
      .returning({ id: feedSnapshot.id });
    g.__vqFeed = { id: row.id, feed };
    const [old] = await db.select({ id: feedSnapshot.id }).from(feedSnapshot).orderBy(desc(feedSnapshot.id)).offset(KEEP - 1).limit(1);
    if (old) await db.delete(feedSnapshot).where(lt(feedSnapshot.id, old.id));
    await db
      .update(feedState)
      .set({ refreshingSince: null, lastOkAt: new Date(), lastError: feed.errors.length ? feed.errors.join(" · ").slice(0, 500) : null, lastDurationMs: Date.now() - t0, runs: sql`${feedState.runs} + 1` })
      .where(eq(feedState.id, 1));
    // Pages et API régénérées à la prochaine visite
    try {
      revalidatePath("/");
      revalidatePath("/api/cves");
      revalidateTag("daily-feed", { expire: 0 });
    } catch {
      /* appelé pendant un rendu (premier instantané) : la page lit déjà le nouvel instantané */
    }
    return { ran: true, generatedAt: feed.generatedAt, total: feed.vulns.length, added: added.length, ms: Date.now() - t0 };
  } catch (e) {
    if ((e as { digest?: string })?.digest === "DYNAMIC_SERVER_USAGE") {
      await db.update(feedState).set({ refreshingSince: null }).where(eq(feedState.id, 1));
      throw e;
    }
    const msg = e instanceof Error ? e.message : String(e);
    await db.update(feedState).set({ refreshingSince: null, lastError: msg.slice(0, 500), lastDurationMs: Date.now() - t0 }).where(eq(feedState.id, 1));
    console.error(`[collecte] échec : ${msg}`);
    return { ran: true, error: msg, ms: Date.now() - t0 };
  }
}

/** Flux à afficher : le dernier instantané, ou un premier calcul s'il n'y en a pas encore (ou sans base). */
export async function currentFeed(): Promise<Feed> {
  try {
    const f = await latestFeed();
    if (f) return f;
    await refreshFeed({ force: true });
    const g2 = await latestFeed();
    if (g2) return g2;
  } catch (e) {
    console.error(`[collecte] lecture de l'instantané impossible : ${e instanceof Error ? e.message : e}`);
  }
  return getDailyFeed();
}

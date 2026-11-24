/**
 * SecurityContext (ProjectDiscovery) — client de l'API REST https://api.securitycontext.com.
 *
 * C'est l'équivalent, côté serveur, du serveur MCP https://mcp.securitycontext.com
 * (get_security_context ↔ GET /v1/{nom}/{id}, search_security_context ↔ GET /v1/{type}?filtres,
 * create_security_context ↔ POST /v1/scans).
 *
 * - Gratuit et sans clé : 60 requêtes / min et 3 nouvelles analyses / h par adresse. Une clé optionnelle
 *   (SECURITYCONTEXT_API_KEY, envoyée en X-Api-Key) donne des limites plus hautes.
 * - Toutes les réponses sont mises en cache en base (partagées : données publiques) et revalidées par ETag ;
 *   un 429 suspend les appels jusqu'au délai indiqué (Retry-After).
 * - Accès : les opérateurs de la plateforme (VIGILANTIQ_ANALYSTS) toujours ; les organisations clientes
 *   seulement si SECURITYCONTEXT_CLIENTS=1. Les conditions de ProjectDiscovery (§ 4.3 h) interdisent de mettre
 *   le service à disposition d'autres personnes que vos utilisateurs autorisés sans accord signé.
 *   SECURITYCONTEXT_ENABLED=0 coupe tout.
 */
import { eq } from "drizzle-orm";
import { getDb } from "@/db";
import { scCache } from "@/db/schema";
import { isAnalyst } from "./cti/leakstore";
import { CVE_RE, readCve, readFeed, readRepo, type Escalation, type ScCve, type ScRepoView } from "./sc-core";

const BASE = () => (process.env.SECURITYCONTEXT_API_URL || "https://api.securitycontext.com").replace(/\/+$/, "");
const UA = "VigilantIQ/1.0 (+https://vigilantiq.io)";

export const ATTRIBUTION = { label: "SecurityContext par ProjectDiscovery", url: "https://securitycontext.com" };

/** Intégration active pour cet utilisateur ? */
export function scAllowed(email: string | null | undefined): boolean {
  if (process.env.SECURITYCONTEXT_ENABLED === "0") return false;
  return process.env.SECURITYCONTEXT_CLIENTS === "1" || isAnalyst(email);
}

export class ScError extends Error {
  constructor(
    message: string,
    public status = 502,
  ) {
    super(message);
  }
}

// Suspension après un 429 (par instance) : on n'insiste pas, conformément à l'usage loyal demandé.
const g = globalThis as unknown as { __vqScPause?: number };

interface Cached {
  status: number;
  body: unknown;
}

/**
 * GET mis en cache : servi depuis la base s'il a moins de `ttlMs`, sinon revalidé (If-None-Match).
 * Une réponse 404 (« inconnu de l'index ») est aussi mise en cache.
 */
async function getJson(path: string, ttlMs: number): Promise<Cached> {
  const db = getDb();
  const [cur] = await db.select().from(scCache).where(eq(scCache.key, path));
  if (cur && Date.now() - cur.fetchedAt.getTime() < ttlMs) return { status: cur.status, body: cur.body };
  if ((g.__vqScPause ?? 0) > Date.now()) {
    if (cur) return { status: cur.status, body: cur.body };
    throw new ScError("SecurityContext limite momentanément les requêtes : réessayez dans une minute.", 429);
  }
  const headers: Record<string, string> = { Accept: "application/json", "User-Agent": UA };
  if (process.env.SECURITYCONTEXT_API_KEY) headers["X-Api-Key"] = process.env.SECURITYCONTEXT_API_KEY;
  if (cur?.etag) headers["If-None-Match"] = cur.etag;
  let res: Response;
  try {
    res = await fetch(BASE() + path, { headers, signal: AbortSignal.timeout(15_000), cache: "no-store" });
  } catch (e) {
    if (cur) return { status: cur.status, body: cur.body };
    throw new ScError(`SecurityContext injoignable (${e instanceof Error ? e.message : e})`);
  }
  if (res.status === 304 && cur) {
    await db.update(scCache).set({ fetchedAt: new Date() }).where(eq(scCache.key, path));
    return { status: cur.status, body: cur.body };
  }
  if (res.status === 429) {
    const wait = Math.min(Number(res.headers.get("retry-after")) || 60, 600);
    g.__vqScPause = Date.now() + wait * 1000;
    if (cur) return { status: cur.status, body: cur.body };
    throw new ScError("SecurityContext limite momentanément les requêtes : réessayez dans une minute.", 429);
  }
  if (res.status !== 200 && res.status !== 404) {
    if (cur) return { status: cur.status, body: cur.body };
    throw new ScError(`SecurityContext a répondu ${res.status}`);
  }
  const body = (await res.json().catch(() => null)) as unknown;
  const row = { key: path, status: res.status, etag: res.headers.get("etag"), body: body as object, fetchedAt: new Date() };
  await db.insert(scCache).values(row).onConflictDoUpdate({ target: scCache.key, set: row });
  return { status: res.status, body };
}

/** Contexte d'une CVE : exploitation (CISA, VulnCheck), exploits publics, Nuclei, exposition, produits. */
export async function cveContext(id: string): Promise<ScCve | null> {
  if (!CVE_RE.test(id)) throw new ScError("Identifiant CVE invalide.", 400);
  const r = await getJson(`/v1/cves/${id}`, 6 * 3600_000);
  return r.status === 200 ? readCve(r.body as Record<string, unknown>) : null;
}

/** Escalades des 30 derniers jours (flux public, hors quota, mis à jour avec le jeu de données). */
export async function escalations(): Promise<Escalation[]> {
  const r = await getJson("/v1/feed?format=json", 15 * 60_000);
  return r.status === 200 ? readFeed(r.body as Record<string, unknown>) : [];
}

/** Escalades touchant les dépendances d'un dépôt suivi. */
export async function repoEscalations(repo: string): Promise<Escalation[]> {
  const r = await getJson(`/v1/feed?format=json&stack=${encodeURIComponent(repo)}`, 60 * 60_000);
  return r.status === 200 ? readFeed(r.body as Record<string, unknown>) : [];
}

/** Contexte d'un dépôt public : score de risque, chemin le plus simple pour un attaquant, mises à jour à faire. */
export async function repoContext(repo: string): Promise<ScRepoView> {
  const fields = "repository,stars,last_pushed_at,risk_score,risk_percentile,severity,counts,dependency_scan";
  const main = await getJson(`/v1/repositories/${repo}?fields=${fields}`, 12 * 3600_000);
  if (main.status !== 200) return readRepo(repo, main.body as Record<string, unknown>, null, null);
  const [risk, stack] = await Promise.all([
    getJson(`/v1/repositories/${repo}/risk`, 12 * 3600_000).catch(() => null),
    getJson(`/v1/repositories/${repo}/stack?status=affected&limit=100`, 12 * 3600_000).catch(() => null),
  ]);
  return readRepo(
    repo,
    main.body as Record<string, unknown>,
    risk?.status === 200 ? (risk.body as Record<string, unknown>) : null,
    stack?.status === 200 ? (stack.body as Record<string, unknown>) : null,
  );
}

/** Lance l'analyse d'un dépôt public absent de l'index (3 nouvelles analyses / h par adresse). */
export async function startScan(repo: string): Promise<{ id: string; status: string }> {
  const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA };
  if (process.env.SECURITYCONTEXT_API_KEY) headers["X-Api-Key"] = process.env.SECURITYCONTEXT_API_KEY;
  const res = await fetch(`${BASE()}/v1/scans`, { method: "POST", headers, body: JSON.stringify({ repository: repo }), signal: AbortSignal.timeout(15_000) });
  const j = (await res.json().catch(() => ({}))) as { id?: string; status?: string; code?: string; error?: string; retry_after_seconds?: number };
  if (res.status === 429)
    throw new ScError(
      j.code === "queue_full" ? "La file d'analyse de SecurityContext est pleine : réessayez dans quelques minutes." : `Limite de 3 nouvelles analyses par heure atteinte${j.retry_after_seconds ? ` (prochaine dans ${Math.ceil(j.retry_after_seconds / 60)} min)` : ""}.`,
      429,
    );
  if (!res.ok || !j.id) throw new ScError(j.error || `SecurityContext a répondu ${res.status}`, res.status >= 500 ? 502 : 400);
  return { id: j.id, status: j.status ?? "queued" };
}

/** État d'une analyse lancée. Une fois terminée, le contexte du dépôt est relu (cache vidé). */
export async function scanStatus(id: string, repo: string): Promise<{ status: string; step: string | null; error: string | null }> {
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(id)) throw new ScError("Analyse inconnue.", 400);
  const res = await fetch(`${BASE()}/v1/scans/${id}`, { headers: { Accept: "application/json", "User-Agent": UA }, signal: AbortSignal.timeout(15_000), cache: "no-store" });
  const j = (await res.json().catch(() => ({}))) as { status?: string; step?: string; error?: string };
  if (j.status === "done") {
    const { like } = await import("drizzle-orm");
    await getDb().delete(scCache).where(like(scCache.key, `/v1/repositories/${repo}%`));
  }
  return { status: j.status ?? "unknown", step: j.step ?? null, error: j.error ?? null };
}

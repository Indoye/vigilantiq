/**
 * Cluster de recherche du corpus dark web : OpenSearch ou Elasticsearch (API REST commune : _bulk, _search, percolate).
 *
 * Configuration (variables d'environnement, jamais affichées) :
 * - DARKWEB_SEARCH_URL : https://… du cluster (OpenSearch Service, Elastic Cloud…) ;
 * - DARKWEB_SEARCH_API_KEY (Elastic : « ApiKey » encodée) ou DARKWEB_SEARCH_USER + DARKWEB_SEARCH_PASSWORD ;
 * - DARKWEB_SEARCH_PREFIX : préfixe des index (vigilantiq par défaut).
 *
 * Deux index :
 * - <préfixe>-dw-pages : pages déjà masquées (texte, empreintes d'e-mails, domaines, portefeuilles) ;
 * - <préfixe>-dw-patterns : motifs des organisations stockés comme requêtes « percolator » — chaque nouvelle page
 *   est confrontée en une seule requête à tous les motifs de toutes les organisations.
 */
import { publicHttpsUrl } from "../netguard.ts";

export type PatternKind = "keyword" | "phrase" | "regex" | "domain" | "email" | "wallet";
export const PATTERN_KINDS: PatternKind[] = ["keyword", "phrase", "regex", "domain", "email", "wallet"];

export interface PageDoc {
  url: string;
  host: string;
  source_id: number | null;
  run_id: string;
  text: string;
  email_hashes: string[];
  email_domains: string[];
  wallets: string[];
  onion_links: string[];
  counts: Record<string, number>;
  keyword_hit: boolean;
  collected_at: string;
}

export class SearchError extends Error {}

const TIMEOUT = 25_000;

export function searchConfigured(): boolean {
  return Boolean(process.env.DARKWEB_SEARCH_URL && (process.env.DARKWEB_SEARCH_API_KEY || process.env.DARKWEB_SEARCH_USER));
}

const prefix = () => (process.env.DARKWEB_SEARCH_PREFIX || "vigilantiq").toLowerCase().replace(/[^a-z0-9_-]/g, "");
export const PAGES = () => `${prefix()}-dw-pages`;
export const PATTERNS = () => `${prefix()}-dw-patterns`;

let base: string | null = null;
function baseUrl(): string {
  if (base) return base;
  const raw = process.env.DARKWEB_SEARCH_URL ?? "";
  // En test local, un cluster http://localhost est permis explicitement
  if (process.env.DARKWEB_SEARCH_ALLOW_LOCAL === "true" && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/?$/.test(raw)) base = raw.replace(/\/+$/, "");
  else base = publicHttpsUrl(raw, "Cluster de recherche").replace(/\/+$/, "");
  return base;
}

function authHeader(): string {
  const k = process.env.DARKWEB_SEARCH_API_KEY;
  if (k) return k.startsWith("ApiKey ") || k.startsWith("Bearer ") ? k : `ApiKey ${k}`;
  return `Basic ${Buffer.from(`${process.env.DARKWEB_SEARCH_USER ?? ""}:${process.env.DARKWEB_SEARCH_PASSWORD ?? ""}`).toString("base64")}`;
}

async function call<T = Record<string, unknown>>(method: string, path: string, body?: unknown, ndjson = false): Promise<T> {
  const res = await fetch(`${baseUrl()}${path}`, {
    method,
    headers: { Authorization: authHeader(), "Content-Type": ndjson ? "application/x-ndjson" : "application/json", Accept: "application/json" },
    body: body === undefined ? undefined : ndjson ? (body as string) : JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT),
  });
  const txt = await res.text();
  let j: unknown = {};
  try {
    j = txt ? JSON.parse(txt) : {};
  } catch {
    j = { raw: txt.slice(0, 200) };
  }
  if (!res.ok) {
    const reason = (j as { error?: { reason?: string; type?: string } | string }).error;
    const msg = typeof reason === "string" ? reason : (reason?.reason ?? reason?.type ?? `HTTP ${res.status}`);
    const e = new SearchError(`Cluster de recherche : ${msg}`);
    (e as SearchError & { status?: number }).status = res.status;
    throw e;
  }
  return j as T;
}

// ---------- Index ----------

const PAGE_PROPS = {
  url: { type: "keyword" },
  host: { type: "keyword" },
  source_id: { type: "integer" },
  run_id: { type: "keyword" },
  text: { type: "text", analyzer: "standard" },
  email_hashes: { type: "keyword" },
  email_domains: { type: "keyword" },
  wallets: { type: "keyword" },
  onion_links: { type: "keyword" },
  counts: {
    properties: Object.fromEntries(["emails", "secrets", "credentials", "phones", "cards", "ips", "ibans"].map((k) => [k, { type: "integer" }])),
  },
  keyword_hit: { type: "boolean" },
  collected_at: { type: "date" },
};

let ensured = false;
/** Crée les deux index s'ils n'existent pas (idempotent). */
export async function ensureIndices(): Promise<void> {
  if (ensured) return;
  const make = async (name: string, mappings: unknown) => {
    try {
      await call("PUT", `/${name}`, { mappings });
    } catch (e) {
      const m = e instanceof Error ? e.message : "";
      if (!/resource_already_exists|already exists/i.test(m)) throw e;
    }
  };
  await make(PAGES(), { dynamic: "strict", properties: PAGE_PROPS });
  await make(PATTERNS(), {
    dynamic: "strict",
    properties: { ...PAGE_PROPS, query: { type: "percolator" }, org_id: { type: "keyword" }, pattern_id: { type: "integer" }, active: { type: "boolean" } },
  });
  ensured = true;
}

// ---------- Motifs → requêtes ----------

/** Contrôle d'un motif avant enregistrement ; renvoie la valeur normalisée. */
export function normalizePattern(kind: PatternKind, raw: string): string {
  const v = raw.trim();
  if (!v) throw new SearchError("Valeur du motif obligatoire.");
  if (v.length > 200) throw new SearchError("Motif trop long (200 caractères au plus).");
  switch (kind) {
    case "keyword":
    case "phrase":
      if (v.replace(/[^\p{L}\p{N}]/gu, "").length < 3) throw new SearchError("Au moins 3 lettres ou chiffres.");
      return v;
    case "regex":
      if (/\s/.test(v)) throw new SearchError("L’expression régulière s’applique mot par mot : pas d’espace.");
      if (v.replace(/[^\p{L}\p{N}]/gu, "").length < 3) throw new SearchError("Expression trop large : au moins 3 caractères littéraux.");
      if (/^\.\*|^\.\+/.test(v) && v.length < 6) throw new SearchError("Expression trop large.");
      return v;
    case "domain": {
      const d = v.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!/^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$/.test(d)) throw new SearchError("Domaine invalide (ex. entreprise.sn).");
      return d;
    }
    case "email":
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) throw new SearchError("Adresse e-mail invalide.");
      return v.toLowerCase();
    case "wallet":
      if (!/^[A-Za-z0-9]{25,100}$/.test(v)) throw new SearchError("Adresse de portefeuille invalide.");
      return v;
  }
}

/** Pour un motif e-mail (empreinte), on surligne le domaine visible dans le texte masqué. */
export function highlightFor(kind: PatternKind, display: string): Record<string, unknown> | undefined {
  if (kind !== "email") return undefined;
  const d = display.split("@")[1];
  return d ? { match_phrase: { text: d } } : undefined;
}

/** Requête OpenSearch/Elasticsearch d'un motif (value déjà normalisée ; pour un e-mail, son empreinte). */
export function patternQuery(kind: PatternKind, value: string): Record<string, unknown> {
  switch (kind) {
    case "keyword":
      return { match: { text: { query: value, operator: "and" } } };
    case "phrase":
      return { match_phrase: { text: { query: value, slop: 1 } } };
    case "regex":
      return { regexp: { text: { value: value.toLowerCase(), flags: "ALL", case_insensitive: true, max_determinized_states: 10000 } } };
    case "domain":
      return { bool: { should: [{ term: { email_domains: value } }, { match_phrase: { text: value } }, { term: { host: value } }], minimum_should_match: 1 } };
    case "email":
      return { term: { email_hashes: value } };
    case "wallet":
      return { bool: { should: [{ term: { wallets: value } }, { match_phrase: { text: value } }], minimum_should_match: 1 } };
  }
}

export async function putPattern(p: { id: number; orgId: string; kind: PatternKind; value: string; active: boolean }): Promise<void> {
  await ensureIndices();
  await call("PUT", `/${PATTERNS()}/_doc/${p.id}?refresh=true`, { query: patternQuery(p.kind, p.value), org_id: p.orgId, pattern_id: p.id, active: p.active });
}

export async function deletePattern(id: number): Promise<void> {
  try {
    await call("DELETE", `/${PATTERNS()}/_doc/${id}?refresh=true`);
  } catch (e) {
    if ((e as { status?: number }).status !== 404) throw e;
  }
}

// ---------- Pages ----------

export async function bulkIndex(docs: { id: string; doc: PageDoc }[]): Promise<number> {
  if (!docs.length) return 0;
  await ensureIndices();
  const body = docs.map((d) => `${JSON.stringify({ index: { _index: PAGES(), _id: d.id } })}\n${JSON.stringify(d.doc)}\n`).join("");
  const r = await call<{ errors: boolean; items: { index: { status: number; error?: { reason?: string } } }[] }>("POST", "/_bulk?refresh=wait_for", body, true);
  const failed = r.items.filter((i) => i.index.status >= 300);
  if (failed.length) console.error(`[dark web] indexation : ${failed.length} échec(s) — ${failed[0].index.error?.reason ?? ""}`);
  return docs.length - failed.length;
}

/** Confronte des pages à tous les motifs actifs : renvoie, pour chaque page, les motifs qui la touchent. */
export async function percolate(docs: PageDoc[]): Promise<{ slot: number; orgId: string; patternId: number }[]> {
  if (!docs.length) return [];
  await ensureIndices();
  const out: { slot: number; orgId: string; patternId: number }[] = [];
  let from = 0;
  for (;;) {
    const r = await call<{ hits: { hits: { _source: { org_id: string; pattern_id: number }; fields?: { _percolator_document_slot?: number[] } }[]; total: { value: number } | number } }>(
      "POST",
      `/${PATTERNS()}/_search`,
      {
        from,
        size: 500,
        _source: ["org_id", "pattern_id"],
        query: { bool: { filter: [{ term: { active: true } }, { percolate: { field: "query", documents: docs } }] } },
      },
    );
    for (const h of r.hits.hits) for (const slot of h.fields?._percolator_document_slot ?? [0]) out.push({ slot, orgId: h._source.org_id, patternId: h._source.pattern_id });
    const total = typeof r.hits.total === "number" ? r.hits.total : r.hits.total.value;
    from += r.hits.hits.length;
    if (!r.hits.hits.length || from >= total || from >= 5000) break;
  }
  return out;
}

export interface Hit {
  id: string;
  url: string;
  host: string;
  collectedAt: string;
  snippet: string;
  counts: Record<string, number>;
}

const HIGHLIGHT = { fields: { text: { fragment_size: 220, number_of_fragments: 2, pre_tags: ["«"], post_tags: ["»"] } } };

function toHit(h: { _id: string; _source: PageDoc; highlight?: { text?: string[] } }): Hit {
  const frag = h.highlight?.text?.join(" … ") ?? (h._source.text ?? "").slice(0, 300);
  return { id: h._id, url: h._source.url, host: h._source.host, collectedAt: h._source.collected_at, snippet: frag, counts: h._source.counts ?? {} };
}

/** Pages du corpus qui correspondent à un motif (recherche rétroactive ou ad hoc), les plus récentes d'abord. */
export async function searchPages(
  query: Record<string, unknown>,
  opts: { size?: number; ids?: string[]; since?: string; highlightQuery?: Record<string, unknown> } = {},
): Promise<{ total: number; hits: Hit[] }> {
  await ensureIndices();
  const filter: unknown[] = [];
  if (opts.ids) filter.push({ ids: { values: opts.ids } });
  if (opts.since) filter.push({ range: { collected_at: { gte: opts.since } } });
  const r = await call<{ hits: { total: { value: number } | number; hits: { _id: string; _source: PageDoc; highlight?: { text?: string[] } }[] } }>("POST", `/${PAGES()}/_search`, {
    size: Math.min(opts.size ?? 20, 200),
    track_total_hits: 10000,
    query: { bool: { must: [query], filter } },
    sort: [{ collected_at: "desc" }],
    _source: { excludes: ["text"] },
    highlight: { ...HIGHLIGHT, require_field_match: false, ...(opts.highlightQuery ? { highlight_query: opts.highlightQuery } : {}) },
  });
  const total = typeof r.hits.total === "number" ? r.hits.total : r.hits.total.value;
  // Sans le texte complet dans _source, le surlignage reste disponible ; toHit ne s'en sert que s'il manque.
  return { total, hits: r.hits.hits.map((h) => toHit({ ...h, _source: { ...h._source, text: h._source.text ?? "" } })) };
}

/** Extraits surlignés d'une liste de pages pour une requête donnée (une requête par lot). */
export async function snippetsFor(query: Record<string, unknown>, ids: string[], highlightQuery?: Record<string, unknown>): Promise<Map<string, string>> {
  const r = await searchPages(query, { ids, size: ids.length, highlightQuery });
  return new Map(r.hits.map((h) => [h.id, h.snippet]));
}

export async function corpusStats(): Promise<{ pages: number; hosts: number; last: string | null }> {
  await ensureIndices();
  const r = await call<{ hits: { total: { value: number } | number }; aggregations: { hosts: { value: number }; last: { value_as_string?: string } } }>("POST", `/${PAGES()}/_search`, {
    size: 0,
    track_total_hits: true,
    aggs: { hosts: { cardinality: { field: "host" } }, last: { max: { field: "collected_at" } } },
  });
  const total = typeof r.hits.total === "number" ? r.hits.total : r.hits.total.value;
  return { pages: total, hosts: r.aggregations.hosts.value, last: r.aggregations.last.value_as_string ?? null };
}

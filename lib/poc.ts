/**
 * Moniteur de codes d'exploitation et de PoC publics.
 *
 * Sources :
 * - PoC-in-GitHub (github.com/nomi-sec/PoC-in-GitHub) : index quotidien des dépôts GitHub par CVE ;
 * - la recherche GitHub : dépôts créés récemment dont le nom ou la description cite une CVE ;
 * - Exploit-DB : via le flux RSS déjà suivi.
 * L'enregistrement en base et la passe quotidienne sont dans exploitstore.ts.
 */
import type { ExploitRef, RssItem } from "./types.ts";

/* eslint-disable @typescript-eslint/no-explicit-any */

const UA = "vigilantiq/0.3 (+https://vercel.com)";
const POC_INDEX = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master";
const CVE_LOOSE_RE = /CVE[-_](\d{4})[-_](\d{4,7})/gi;

/** Identifiants CVE cités dans un texte, y compris écrits « CVE_2026_1234 ». */
export function cvesIn(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(CVE_LOOSE_RE)) out.add(`CVE-${m[1]}-${m[2]}`);
  return [...out];
}

function repoToExploit(r: any, cveId: string): ExploitRef | null {
  const url = String(r?.html_url ?? "");
  if (!url.startsWith("https://github.com/") || r?.fork) return null;
  return {
    url,
    cveId,
    source: "github",
    title: String(r.full_name ?? r.name ?? url.replace("https://github.com/", "")),
    description: String(r.description ?? "").slice(0, 300),
    stars: Number(r.stargazers_count ?? 0),
    publishedAt: r.created_at ? new Date(r.created_at).toISOString() : null,
    firstSeen: null,
  };
}

/** Fiche PoC-in-GitHub d'une CVE (liste de dépôts). */
export function parsePocIndex(json: unknown, cveId: string): ExploitRef[] {
  if (!Array.isArray(json)) return [];
  return json.map((r) => repoToExploit(r, cveId)).filter((x): x is ExploitRef => x !== null);
}

/** Dépôts PoC connus pour une CVE, d'après PoC-in-GitHub (mis en cache 6 h). */
export async function fetchPocIndex(cveId: string): Promise<ExploitRef[]> {
  const year = cveId.split("-")[1];
  const res = await fetch(`${POC_INDEX}/${year}/${cveId}.json`, {
    headers: { "User-Agent": UA },
    signal: AbortSignal.timeout(10_000),
    next: { revalidate: 6 * 3600 },
  });
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`PoC-in-GitHub a répondu ${res.status}`);
  const text = await res.text();
  if (!text.trimStart().startsWith("[")) return [];
  return parsePocIndex(JSON.parse(text), cveId);
}

/** Résultats de la recherche GitHub → une entrée par (dépôt, CVE citée). */
export function parseGithubSearch(json: any): ExploitRef[] {
  const out: ExploitRef[] = [];
  for (const r of json?.items ?? []) {
    const ids = cvesIn(`${r.name ?? ""} ${r.description ?? ""} ${(r.topics ?? []).join(" ")}`);
    for (const id of ids.slice(0, 5)) {
      const e = repoToExploit(r, id);
      if (e) out.push(e);
    }
  }
  return out;
}

/** Dépôts créés depuis `sinceHours` heures qui citent une CVE. GITHUB_TOKEN relève la limite de requêtes. */
export async function searchRecentGithub(sinceHours = 48, pages = 3): Promise<ExploitRef[]> {
  const since = new Date(Date.now() - sinceHours * 3600_000).toISOString().slice(0, 10);
  const headers: Record<string, string> = { "User-Agent": UA, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const out: ExploitRef[] = [];
  for (let page = 1; page <= pages; page++) {
    const q = encodeURIComponent(`CVE in:name,description created:>=${since} fork:false`);
    const res = await fetch(`https://api.github.com/search/repositories?q=${q}&sort=updated&order=desc&per_page=100&page=${page}`, {
      headers,
      signal: AbortSignal.timeout(15_000),
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`recherche GitHub : ${res.status}`);
    const json = await res.json();
    out.push(...parseGithubSearch(json));
    if ((json.items ?? []).length < 100) break;
  }
  return out;
}

/** Exploits publiés sur Exploit-DB, repérés dans le flux RSS. */
export function exploitsFromRss(items: RssItem[]): ExploitRef[] {
  return items
    .filter((it) => it.kind === "exploit")
    .flatMap((it) =>
      it.cves.slice(0, 5).map((cveId) => ({
        url: it.link,
        cveId,
        source: it.sourceId === "exploitdb" ? "exploitdb" : it.sourceId,
        title: it.title,
        description: it.summary.slice(0, 300),
        stars: 0,
        publishedAt: it.published || null,
        firstSeen: null,
      })),
    );
}

/** Trie du plus crédible au moins crédible : Exploit-DB, puis étoiles, puis ancienneté. */
export function rankExploits(list: ExploitRef[]): ExploitRef[] {
  const seen = new Set<string>();
  return list
    .filter((e) => (seen.has(e.url) ? false : (seen.add(e.url), true)))
    .sort((a, b) => Number(b.source === "exploitdb") - Number(a.source === "exploitdb") || b.stars - a.stars || (a.publishedAt ?? "").localeCompare(b.publishedAt ?? ""));
}

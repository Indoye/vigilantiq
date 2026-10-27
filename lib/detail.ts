import { summarizeFr, translateGuidanceFr } from "./ai.ts";
import { fetchCveOrg } from "./cveorg.ts";
import { exploitsFor, saveExploits } from "./exploitstore";
import { buildVuln, enrich, errorText, rawFromCveOrg } from "./feed.ts";
import { exploitsFromRss, fetchPocIndex, rankExploits } from "./poc";
import { buildRemediation } from "./remediation";
import { ticketsFor } from "./ticketstore";
import { dbLinks } from "./references.ts";
import { getRssSnapshot, mentionIndex } from "./rss.ts";
import { fetchEpss, fetchKev, fetchNvdOne, fetchOsv } from "./sources.ts";
import type { CveDetail } from "./types.ts";
import { mergeAffected, osvAffected } from "./versions.ts";

export const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/;

/** Fiche complète d'une CVE : NVD + CVE.org (éditeur) + OSV + EPSS + KEV + flux RSS + résumé IA. */
export async function getCveDetail(idIn: string): Promise<CveDetail | null> {
  const id = idIn.toUpperCase();
  if (!CVE_ID_RE.test(id)) return null;
  const errors: string[] = [];

  const [nvdR, cnaR, osvR, epssR, kevR, rssR, pocR, storedR, ticketsR] = await Promise.allSettled([
    fetchNvdOne(id),
    fetchCveOrg(id),
    fetchOsv(id),
    fetchEpss([id]),
    fetchKev(),
    getRssSnapshot(30),
    fetchPocIndex(id),
    exploitsFor([id]),
    ticketsFor(id),
  ]);
  const val = <T,>(r: PromiseSettledResult<T>, name: string): T | null => {
    if (r.status === "fulfilled") return r.value;
    errors.push(errorText(name, r.reason));
    return null;
  };
  const nvd = val(nvdR, "NVD");
  const cna = val(cnaR, "CVE.org");
  const osv = val(osvR, "OSV");
  const epss = val(epssR, "EPSS");
  const kev = val(kevR, "CISA KEV");
  const rss = val(rssR, "Flux RSS");
  const pocLive = val(pocR, "PoC-in-GitHub") ?? [];
  const stored = storedR.status === "fulfilled" ? storedR.value.get(id) ?? [] : [];
  const tickets = ticketsR.status === "fulfilled" ? ticketsR.value : [];

  if (!nvd && !cna) return null;

  const { raw, ssvc } = nvd ? enrich(nvd, cna) : { raw: rawFromCveOrg(cna!), ssvc: cna!.ssvc };
  const osvList = osv ? osvAffected(osv) : [];
  raw.affected = mergeAffected(raw.affected, osvList);
  if (Array.isArray(osv?.references)) {
    const OSV_TAG: Record<string, string> = { FIX: "patch", ADVISORY: "third-party-advisory", REPORT: "issue-tracking", ARTICLE: "technical-description" };
    raw.references = [
      ...raw.references,
      ...osv.references.map((r: { url: string; type?: string }) => ({ url: r.url, tags: r.type && OSV_TAG[r.type] ? [OSV_TAG[r.type]] : [] })),
    ];
  }

  const mentions = rss ? mentionIndex(rss.items).get(id) ?? [] : [];
  const fromRss = rss ? exploitsFromRss(rss.items).filter((e) => e.cveId === id) : [];
  const exploits = rankExploits([...stored, ...pocLive, ...fromRss]);
  // Les PoC trouvés en direct enrichissent la base partagée (sans bloquer la fiche en cas d'échec).
  const known = new Set(stored.map((e) => e.url));
  const fresh = exploits.filter((e) => !known.has(e.url));
  if (fresh.length) await saveExploits(fresh).catch((e) => console.error(`[exploits] ${e instanceof Error ? e.message : e}`));

  const vuln = buildVuln(raw, "nvd", { kev: kev?.get(id), epss: epss?.get(id), mentions, ssvc, exploits });

  // Même cache que le tableau : une CVE déjà résumée dans le flux du jour ne coûte pas un second appel.
  const { summaries, errors: aiErrors } = await summarizeFr([vuln]);
  const ai = summaries.get(id);
  if (ai) vuln.ai = ai;
  for (const e of aiErrors) console.error(`[résumés IA] ${e}`);

  // Plan de remédiation, puis traduction des consignes d'origine (éditeur, CISA) quand l'IA est disponible.
  const remediation = buildRemediation(vuln, { solutions: cna?.solutions, workarounds: cna?.workarounds });
  const withOriginal = remediation.steps.filter((st) => st.original);
  const fr = await translateGuidanceFr(id, withOriginal.map((st) => st.original!));
  if (fr) withOriginal.forEach((st, i) => (st.originalFr = fr[i]));

  return {
    ...vuln,
    exploits,
    remediation,
    tickets,
    lastModified: raw.lastModified ?? cna?.updated ?? null,
    state: cna?.state ?? null,
    cna: cna?.cna ?? null,
    dbLinks: dbLinks(id, { kev: Boolean(vuln.kev), osv: osvList.length > 0 }),
    errors,
  };
}

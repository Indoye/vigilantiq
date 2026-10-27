import { summarizeFr } from "./ai.ts";
import { fetchCveOrg } from "./cveorg.ts";
import { buildVuln, enrich, errorText, rawFromCveOrg } from "./feed.ts";
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

  const [nvdR, cnaR, osvR, epssR, kevR, rssR] = await Promise.allSettled([
    fetchNvdOne(id),
    fetchCveOrg(id),
    fetchOsv(id),
    fetchEpss([id]),
    fetchKev(),
    getRssSnapshot(30),
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
  const vuln = buildVuln(raw, "nvd", { kev: kev?.get(id), epss: epss?.get(id), mentions, ssvc });

  // Même cache que le tableau : une CVE déjà résumée dans le flux du jour ne coûte pas un second appel.
  const { summaries, errors: aiErrors } = await summarizeFr([vuln]);
  const ai = summaries.get(id);
  if (ai) vuln.ai = ai;
  for (const e of aiErrors) console.error(`[résumés IA] ${e}`);

  return {
    ...vuln,
    lastModified: raw.lastModified ?? cna?.updated ?? null,
    state: cna?.state ?? null,
    cna: cna?.cna ?? null,
    dbLinks: dbLinks(id, { kev: Boolean(vuln.kev), osv: osvList.length > 0 }),
    errors,
  };
}

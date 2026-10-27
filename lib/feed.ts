import { aiEnabled, summarizeFr } from "./ai.ts";
import { fetchCveOrgMany, type CveOrgData } from "./cveorg.ts";
import { mergeReferences } from "./references.ts";
import { getRssSnapshot, mentionIndex } from "./rss.ts";
import { scoreVuln } from "./score.ts";
import { fetchEpss, fetchKev, fetchNvdWindow, type KevEntry, type RawCve } from "./sources.ts";
import { matchStack, parseStack } from "./stack.ts";
import type { Feed, Mention, RssSnapshot, SourceStatus, Ssvc, Vuln } from "./types.ts";
import { mergeAffected } from "./versions.ts";

const KEV_RECENT_DAYS = 7;
const RSS_RECENT_HOURS = 72;

export function errorText(source: string, e: unknown): string {
  const msg = e instanceof Error ? (e.name === "TimeoutError" ? "délai dépassé" : e.message) : "erreur inconnue";
  return `${source} indisponible (${msg})`;
}

export function rawFromCveOrg(c: CveOrgData): RawCve {
  return {
    id: c.id,
    published: c.published ?? "",
    lastModified: c.updated,
    description: c.description,
    cvss: c.cvss,
    cvssVersion: c.cvssVersion,
    cvssSource: c.cvssSource,
    severity: c.severity,
    vector: c.vector,
    vendors: [...new Set(c.affected.map((a) => a.vendor.toLowerCase()).filter(Boolean))],
    products: [...new Set(c.affected.map((a) => a.product.toLowerCase()).filter(Boolean))],
    cwes: c.cwes,
    references: c.references,
    affected: c.affected,
  };
}

function rawFromKev(k: KevEntry): RawCve {
  return {
    id: k.id,
    published: k.dateAdded,
    lastModified: null,
    description: k.description,
    cvss: null,
    cvssVersion: null,
    cvssSource: null,
    severity: null,
    vector: null,
    vendors: [k.vendor.toLowerCase()],
    products: [k.product.toLowerCase()],
    cwes: [],
    references: [],
    affected: [],
  };
}

/** Complète une fiche NVD avec la fiche de l'éditeur (CVE.org) : CVSS manquant, versions, références, SSVC. */
export function enrich(raw: RawCve, c?: CveOrgData | null): { raw: RawCve; ssvc: Ssvc | null } {
  if (!c) return { raw, ssvc: null };
  const out: RawCve = { ...raw };
  if (out.cvss == null && c.cvss != null) {
    out.cvss = c.cvss;
    out.cvssVersion = c.cvssVersion;
    out.cvssSource = c.cvssSource;
    out.severity = c.severity;
    out.vector = c.vector;
  }
  if (!out.description) out.description = c.description;
  out.affected = mergeAffected(c.affected, raw.affected);
  out.references = [...raw.references, ...c.references];
  out.cwes = [...new Set([...raw.cwes, ...c.cwes])];
  if (!out.vendors.length) out.vendors = [...new Set(c.affected.map((a) => a.vendor.toLowerCase()).filter(Boolean))];
  if (!out.products.length) out.products = [...new Set(c.affected.map((a) => a.product.toLowerCase()).filter(Boolean))];
  return { raw: out, ssvc: c.ssvc };
}

export function buildVuln(
  raw: RawCve,
  origin: Vuln["origin"],
  extra: { kev?: KevEntry; epss?: { epss: number; percentile: number }; mentions?: Mention[]; ssvc?: Ssvc | null },
): Vuln {
  const k = extra.kev;
  const base = {
    id: raw.id,
    published: raw.published,
    description: raw.description,
    cvss: raw.cvss,
    cvssVersion: raw.cvssVersion,
    cvssSource: raw.cvssSource,
    severity: raw.severity,
    vector: raw.vector,
    vendors: raw.vendors,
    products: raw.products,
    cwes: raw.cwes,
    references: mergeReferences(raw.references),
    affected: raw.affected,
    origin,
    epss: extra.epss?.epss ?? null,
    epssPercentile: extra.epss?.percentile ?? null,
    kev: k ? { name: k.name, dateAdded: k.dateAdded, dueDate: k.dueDate, ransomware: k.ransomware, action: k.action } : null,
    ssvc: extra.ssvc ?? null,
    mentions: extra.mentions ?? [],
  };
  return { ...base, ...scoreVuln(base) };
}

/**
 * Flux du jour :
 * NVD (fenêtre glissante) + ajouts récents CISA KEV + CVE citées dans les flux RSS,
 * enrichies par CVE.org (versions de l'éditeur, SSVC), EPSS, puis scorées et résumées.
 */
export async function getDailyFeed(rssIn?: RssSnapshot): Promise<Feed> {
  const windowHours = Number(process.env.FEED_WINDOW_HOURS || 24);
  const errors: string[] = [];
  const sources: SourceStatus[] = [];

  const [nvdRes, kevRes, rssRes] = await Promise.allSettled([
    fetchNvdWindow(windowHours),
    fetchKev(),
    rssIn ? Promise.resolve(rssIn) : getRssSnapshot(),
  ]);
  const nvd = nvdRes.status === "fulfilled" ? nvdRes.value : [];
  if (nvdRes.status === "rejected") errors.push(errorText("NVD", nvdRes.reason));
  sources.push({ name: "NVD", ok: nvdRes.status === "fulfilled", detail: nvdRes.status === "fulfilled" ? `${nvd.length} CVE` : "indisponible" });

  const kev = kevRes.status === "fulfilled" ? kevRes.value : new Map<string, KevEntry>();
  if (kevRes.status === "rejected") errors.push(errorText("CISA KEV", kevRes.reason));
  sources.push({ name: "CISA KEV", ok: kevRes.status === "fulfilled" });

  const rss = rssRes.status === "fulfilled" ? rssRes.value : { fetchedAt: "", items: [], sources: [] };
  const mentions = mentionIndex(rss.items);

  const entries: { raw: RawCve; origin: Vuln["origin"] }[] = nvd.map((raw) => ({ raw, origin: "nvd" }));
  const seen = new Set(nvd.map((r) => r.id));

  const kevCutoff = Date.now() - KEV_RECENT_DAYS * 86400_000;
  for (const k of kev.values()) {
    if (!seen.has(k.id) && Date.parse(k.dateAdded) >= kevCutoff) {
      entries.push({ raw: rawFromKev(k), origin: "kev" });
      seen.add(k.id);
    }
  }

  // CVE citées récemment par un CERT, un éditeur ou Exploit-DB mais absentes de la fenêtre NVD
  const rssCutoff = Date.now() - RSS_RECENT_HOURS * 3600_000;
  const rssIds = [
    ...new Set(
      rss.items
        .filter((it) => it.kind !== "cve" && (!it.published || Date.parse(it.published) >= rssCutoff))
        .flatMap((it) => it.cves),
    ),
  ]
    .filter((id) => !seen.has(id))
    .slice(0, Number(process.env.RSS_CVE_MAX || 40));

  // CVE.org : obligatoire pour les CVE venues des flux, utile pour les plus graves sans versions ni CVSS
  const needsCna = entries
    .filter(({ raw }) => raw.cvss == null || raw.cvss >= 7 || raw.affected.length === 0)
    .map(({ raw }) => raw.id)
    .slice(0, Number(process.env.CVEORG_MAX || 80));
  const { data: cna, failed } = await fetchCveOrgMany([...rssIds, ...needsCna]);
  if (failed > 0) errors.push(`CVE.org : ${failed} fiche${failed > 1 ? "s" : ""} non récupérée${failed > 1 ? "s" : ""}`);
  sources.push({ name: "CVE.org", ok: failed === 0, detail: `${cna.size} fiches` });

  for (const id of rssIds) {
    const c = cna.get(id);
    if (c && c.state !== "REJECTED") entries.push({ raw: rawFromCveOrg(c), origin: "rss" });
  }

  let epss = new Map<string, { epss: number; percentile: number }>();
  try {
    epss = await fetchEpss(entries.map((e) => e.raw.id));
    sources.push({ name: "FIRST EPSS", ok: true });
  } catch (e) {
    errors.push(errorText("EPSS", e));
    sources.push({ name: "FIRST EPSS", ok: false });
  }

  const vulns: Vuln[] = entries.map(({ raw, origin }) => {
    const { raw: r, ssvc } = origin === "rss" ? { raw, ssvc: cna.get(raw.id)?.ssvc ?? null } : enrich(raw, cna.get(raw.id));
    return buildVuln(r, origin, { kev: kev.get(raw.id), epss: epss.get(raw.id), mentions: mentions.get(raw.id), ssvc });
  });
  vulns.sort((a, b) => b.score - a.score || b.published.localeCompare(a.published));

  // L'IA résume en priorité celles qui touchent la stack de l'équipe, puis les plus graves.
  const maxAi = Number(process.env.AI_MAX_SUMMARIES || 40);
  const teamStack = parseStack(process.env.STACK_KEYWORDS ?? "");
  const toSummarize = [
    ...vulns.filter((v) => matchStack(v, teamStack).length > 0),
    ...vulns.filter((v) => v.priority === "urgente" || v.priority === "haute"),
    ...vulns,
  ]
    .filter((v, i, arr) => arr.findIndex((x) => x.id === v.id) === i)
    .slice(0, maxAi);

  const { summaries, errors: aiErrors } = await summarizeFr(toSummarize);
  errors.push(...aiErrors);
  for (const v of vulns) {
    const s = summaries.get(v.id);
    if (s) v.ai = s;
  }

  const rssOk = rss.sources.filter((s) => s.ok).length;
  sources.push({ name: "Flux RSS", ok: rssOk === rss.sources.length, detail: `${rssOk}/${rss.sources.length} flux` });

  return { generatedAt: new Date().toISOString(), windowHours, vulns, errors, aiEnabled: aiEnabled(), sources };
}

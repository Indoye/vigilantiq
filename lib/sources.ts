import type { AffectedProduct, KevInfo } from "./types.ts";
import { nvdAffected } from "./versions.ts";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";

/** Durée de cache des appels sources (secondes). */
export const SOURCE_REVALIDATE = 3 * 3600;
const UA = "veille-cve/0.2 (+https://vercel.com)";

export interface RawCve {
  id: string;
  published: string;
  lastModified: string | null;
  description: string;
  cvss: number | null;
  cvssVersion: string | null;
  cvssSource: string | null;
  severity: string | null;
  vector: string | null;
  vendors: string[];
  products: string[];
  cwes: string[];
  references: { url: string; tags: string[] }[];
  affected: AffectedProduct[];
}

export interface KevEntry extends KevInfo {
  id: string;
  vendor: string;
  product: string;
  description: string;
}

// ---------- NVD ----------

function nvdDate(d: Date): string {
  // Format attendu par l'API NVD 2.0 : 2026-10-25T07:00:00.000 (UTC)
  return d.toISOString().replace("Z", "");
}

function nvdHeaders(): Record<string, string> {
  const h: Record<string, string> = { "User-Agent": UA };
  if (process.env.NVD_API_KEY) h.apiKey = process.env.NVD_API_KEY;
  return h;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function pickMetric(list: any[] | undefined): any | undefined {
  if (!Array.isArray(list) || list.length === 0) return undefined;
  return list.find((m) => m.type === "Primary") ?? list[0];
}

export function parseNvdItem(item: any): RawCve {
  const c = item.cve ?? {};
  const description: string =
    c.descriptions?.find((d: any) => d.lang === "en")?.value ?? c.descriptions?.[0]?.value ?? "";

  let cvss: number | null = null;
  let cvssVersion: string | null = null;
  let cvssSource: string | null = null;
  let severity: string | null = null;
  let vector: string | null = null;
  const order: [string, string][] = [
    ["cvssMetricV31", "3.1"],
    ["cvssMetricV40", "4.0"],
    ["cvssMetricV30", "3.0"],
    ["cvssMetricV2", "2.0"],
  ];
  for (const [key, version] of order) {
    const m = pickMetric(c.metrics?.[key]);
    if (m?.cvssData?.baseScore != null) {
      cvss = Number(m.cvssData.baseScore);
      cvssVersion = version;
      cvssSource = m.type === "Primary" ? "NVD" : "CNA";
      severity = m.cvssData.baseSeverity ?? m.baseSeverity ?? null;
      vector = m.cvssData.vectorString ?? null;
      break;
    }
  }

  const affected = nvdAffected(c.configurations);
  const vendors = new Set<string>();
  const products = new Set<string>();
  for (const conf of c.configurations ?? []) {
    for (const node of conf.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        const parts = String(match.criteria ?? "").split(":");
        if (parts.length > 5 && match.vulnerable !== false) {
          if (parts[3] && parts[3] !== "*") vendors.add(parts[3]);
          if (parts[4] && parts[4] !== "*") products.add(parts[4]);
        }
      }
    }
  }

  const cwes = new Set<string>();
  for (const w of c.weaknesses ?? []) {
    for (const d of w.description ?? []) {
      if (typeof d.value === "string" && d.value.startsWith("CWE-")) cwes.add(d.value);
    }
  }

  return {
    id: c.id,
    published: c.published,
    lastModified: c.lastModified ?? null,
    description,
    cvss,
    cvssVersion,
    cvssSource,
    severity,
    vector,
    vendors: [...vendors],
    products: [...products],
    cwes: [...cwes],
    references: (c.references ?? []).map((r: any) => ({ url: String(r.url ?? ""), tags: (r.tags ?? []).map(String) })),
    affected,
  };
}

/** CVE publiées dans les `hours` dernières heures (hors CVE rejetées). */
export async function fetchNvdWindow(hours: number): Promise<RawCve[]> {
  const end = new Date();
  const start = new Date(end.getTime() - hours * 3600_000);
  const out: RawCve[] = [];
  let startIndex = 0;
  let total = Infinity;
  while (startIndex < total && startIndex < 10_000) {
    const url =
      `${NVD_URL}?pubStartDate=${nvdDate(start)}&pubEndDate=${nvdDate(end)}` +
      `&noRejected&resultsPerPage=2000&startIndex=${startIndex}`;
    const res = await fetch(url, {
      headers: nvdHeaders(),
      signal: AbortSignal.timeout(25_000),
      next: { revalidate: SOURCE_REVALIDATE },
    });
    if (!res.ok) throw new Error(`NVD a répondu ${res.status}`);
    const json = await res.json();
    total = json.totalResults ?? 0;
    for (const item of json.vulnerabilities ?? []) {
      const parsed = parseNvdItem(item);
      if (parsed.id) out.push(parsed);
    }
    startIndex += json.resultsPerPage || 2000;
  }
  return out;
}

/** Une CVE précise (fiche détaillée). */
export async function fetchNvdOne(id: string): Promise<RawCve | null> {
  const res = await fetch(`${NVD_URL}?cveId=${encodeURIComponent(id)}`, {
    headers: nvdHeaders(),
    signal: AbortSignal.timeout(15_000),
    next: { revalidate: SOURCE_REVALIDATE },
  });
  if (!res.ok) throw new Error(`NVD a répondu ${res.status}`);
  const json = await res.json();
  const item = json.vulnerabilities?.[0];
  return item ? parseNvdItem(item) : null;
}

// ---------- CISA KEV ----------

export async function fetchKev(): Promise<Map<string, KevEntry>> {
  const res = await fetch(KEV_URL, {
    headers: { "User-Agent": UA },
    signal: AbortSignal.timeout(20_000),
    next: { revalidate: SOURCE_REVALIDATE },
  });
  if (!res.ok) throw new Error(`CISA KEV a répondu ${res.status}`);
  const json = await res.json();
  const map = new Map<string, KevEntry>();
  for (const v of json.vulnerabilities ?? []) {
    map.set(v.cveID, {
      id: v.cveID,
      vendor: v.vendorProject ?? "",
      product: v.product ?? "",
      name: v.vulnerabilityName ?? "",
      description: v.shortDescription ?? "",
      dateAdded: v.dateAdded ?? "",
      dueDate: v.dueDate ?? "",
      action: v.requiredAction ?? "",
      ransomware: String(v.knownRansomwareCampaignUse ?? "").toLowerCase() === "known",
    });
  }
  return map;
}

// ---------- FIRST EPSS ----------

export async function fetchEpss(ids: string[]): Promise<Map<string, { epss: number; percentile: number }>> {
  const map = new Map<string, { epss: number; percentile: number }>();
  for (let i = 0; i < ids.length; i += 100) {
    const batch = ids.slice(i, i + 100);
    const res = await fetch(`${EPSS_URL}?cve=${batch.join(",")}&limit=100`, {
      headers: { "User-Agent": UA },
      signal: AbortSignal.timeout(15_000),
      next: { revalidate: SOURCE_REVALIDATE },
    });
    if (!res.ok) throw new Error(`EPSS a répondu ${res.status}`);
    const json = await res.json();
    for (const d of json.data ?? []) {
      map.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile) });
    }
  }
  return map;
}

// ---------- OSV ----------

export async function fetchOsv(id: string): Promise<any | null> {
  const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
    headers: { "User-Agent": UA },
    signal: AbortSignal.timeout(10_000),
    next: { revalidate: SOURCE_REVALIDATE },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`OSV a répondu ${res.status}`);
  return res.json();
}

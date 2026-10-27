import type { Ssvc } from "./types.ts";
import { cnaAffected } from "./versions.ts";
import type { AffectedProduct } from "./types.ts";

/* eslint-disable @typescript-eslint/no-explicit-any */

const CVE_API = "https://cveawg.mitre.org/api/cve/";

export interface CveOrgData {
  id: string;
  state: string | null;
  cna: string | null;
  published: string | null;
  updated: string | null;
  description: string;
  cvss: number | null;
  cvssVersion: string | null;
  cvssSource: string | null;
  severity: string | null;
  vector: string | null;
  cwes: string[];
  references: { url: string; tags: string[] }[];
  affected: AffectedProduct[];
  ssvc: Ssvc | null;
}

function metricFrom(metrics: any[] | undefined): Pick<CveOrgData, "cvss" | "cvssVersion" | "severity" | "vector"> | null {
  for (const [k, ver] of [
    ["cvssV3_1", "3.1"],
    ["cvssV4_0", "4.0"],
    ["cvssV3_0", "3.0"],
    ["cvssV2_0", "2.0"],
  ] as const) {
    const m = (metrics ?? []).find((x) => x?.[k]?.baseScore != null)?.[k];
    if (m) return { cvss: Number(m.baseScore), cvssVersion: ver, severity: m.baseSeverity ?? null, vector: m.vectorString ?? null };
  }
  return null;
}

export function parseCveOrg(rec: any): CveOrgData {
  const meta = rec?.cveMetadata ?? {};
  const cna = rec?.containers?.cna ?? {};
  const adp: any[] = rec?.containers?.adp ?? [];

  const description: string =
    cna.descriptions?.find((d: any) => String(d.lang).startsWith("en"))?.value ?? cna.descriptions?.[0]?.value ?? "";

  let metric = metricFrom(cna.metrics);
  let cvssSource: string | null = metric ? meta.assignerShortName ?? "CNA" : null;
  if (!metric) {
    for (const a of adp) {
      const m = metricFrom(a.metrics);
      if (m) {
        metric = m;
        cvssSource = a.providerMetadata?.shortName ?? "ADP";
        break;
      }
    }
  }

  let ssvc: Ssvc | null = null;
  for (const a of adp) {
    for (const m of a.metrics ?? []) {
      if (m?.other?.type === "ssvc") {
        const opts: any[] = m.other.content?.options ?? [];
        const get = (k: string) => {
          const o = opts.find((x) => x && k in x);
          return o ? String(o[k]).toLowerCase() : null;
        };
        ssvc = { exploitation: get("Exploitation"), automatable: get("Automatable"), technicalImpact: get("Technical Impact") };
      }
    }
  }

  const cwes = new Set<string>();
  for (const pt of [...(cna.problemTypes ?? []), ...adp.flatMap((a) => a.problemTypes ?? [])]) {
    for (const d of pt.descriptions ?? []) if (d.cweId) cwes.add(String(d.cweId));
  }

  const refs = [...(cna.references ?? []), ...adp.flatMap((a) => a.references ?? [])].map((r: any) => ({
    url: String(r.url ?? ""),
    tags: (r.tags ?? []).map(String),
  }));

  return {
    id: meta.cveId,
    state: meta.state ?? null,
    cna: meta.assignerShortName ?? null,
    published: meta.datePublished ?? null,
    updated: meta.dateUpdated ?? null,
    description,
    cvss: metric?.cvss ?? null,
    cvssVersion: metric?.cvssVersion ?? null,
    cvssSource,
    severity: metric?.severity ?? null,
    vector: metric?.vector ?? null,
    cwes: [...cwes],
    references: refs,
    affected: cnaAffected(rec),
    ssvc,
  };
}

export async function fetchCveOrg(id: string, revalidate = 6 * 3600): Promise<CveOrgData | null> {
  const res = await fetch(CVE_API + encodeURIComponent(id), {
    headers: { Accept: "application/json", "User-Agent": "veille-cve/0.2" },
    signal: AbortSignal.timeout(10_000),
    next: { revalidate },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`CVE.org a répondu ${res.status}`);
  return parseCveOrg(await res.json());
}

/** Récupère plusieurs fiches CVE.org avec un parallélisme limité ; les échecs sont ignorés. */
export async function fetchCveOrgMany(ids: string[], concurrency = 8): Promise<{ data: Map<string, CveOrgData>; failed: number }> {
  const data = new Map<string, CveOrgData>();
  let failed = 0;
  let i = 0;
  async function worker() {
    while (i < ids.length) {
      const id = ids[i++];
      try {
        const d = await fetchCveOrg(id);
        if (d) data.set(id, d);
      } catch {
        failed++;
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ids.length) }, worker));
  return { data, failed };
}


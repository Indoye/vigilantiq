import type { DbLink, Reference } from "./types.ts";

const TAGS: Record<string, string> = {
  patch: "Correctif",
  "vendor-advisory": "Avis éditeur",
  exploit: "Exploit",
  "third-party-advisory": "Avis tiers",
  mitigation: "Contournement",
  "release-notes": "Notes de version",
  "issue-tracking": "Suivi de bug",
  "us-government-resource": "Gouv. US",
  "government-resource": "Gouvernement",
  "mailing-list": "Liste de diffusion",
  "technical-description": "Analyse technique",
  "press/media-coverage": "Presse",
  "media-coverage": "Presse",
  "vdb-entry": "Base de vulnérabilités",
  "signature": "Signature",
  "product": "Produit",
  "permissions-required": "Accès restreint",
  "broken-link": "Lien cassé",
};

const RANK = ["Correctif", "Avis éditeur", "Contournement", "Exploit", "Notes de version", "Avis tiers", "Gouv. US", "Gouvernement"];

export function normalizeTag(tag: string): string | null {
  const t = tag
    .toLowerCase()
    .replace(/^x_refsource_/, "")
    .replace(/^x_/, "")
    .trim()
    .replace(/\s+/g, "-");
  if (t === "confirm" || t === "misc" || t === "url") return null;
  return TAGS[t] ?? null;
}

/** Fusionne des références de plusieurs sources, traduit les étiquettes, trie (correctifs et avis d'abord). */
export function mergeReferences(...lists: { url: string; tags?: string[] }[][]): Reference[] {
  const map = new Map<string, Reference>();
  for (const list of lists) {
    for (const r of list) {
      if (!r?.url || !/^https?:\/\//i.test(r.url)) continue;
      const url = r.url.trim();
      const ref = map.get(url) ?? { url, tags: [] };
      for (const t of r.tags ?? []) {
        const n = normalizeTag(t);
        if (n && !ref.tags.includes(n)) ref.tags.push(n);
      }
      map.set(url, ref);
    }
  }
  const rank = (r: Reference) => {
    const idx = r.tags.map((t) => RANK.indexOf(t)).filter((i) => i >= 0);
    return idx.length ? Math.min(...idx) : RANK.length;
  };
  return [...map.values()].filter((r) => !r.tags.includes("Lien cassé")).sort((a, b) => rank(a) - rank(b));
}

/** Liens directs vers les bases de vulnérabilités de référence. */
export function dbLinks(id: string, opts: { kev?: boolean; osv?: boolean } = {}): DbLink[] {
  const year = id.replace(/^CVE-/i, "");
  const links: DbLink[] = [
    { name: "NVD", url: `https://nvd.nist.gov/vuln/detail/${id}`, note: "NIST, scores et configurations" },
    { name: "CVE.org", url: `https://www.cve.org/CVERecord?id=${id}`, note: "Fiche officielle de l'éditeur (CNA)" },
  ];
  if (opts.kev) {
    links.push({
      name: "CISA KEV",
      url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`,
      note: "Catalogue des failles exploitées",
    });
  }
  links.push(
    { name: "OSV", url: `https://osv.dev/vulnerability/${id}`, note: opts.osv ? "Paquets open source touchés" : "Base open source" },
    { name: "GitHub Advisories", url: `https://github.com/advisories?query=${id}`, note: "Avis par écosystème" },
    { name: "CIRCL Vulnerability-Lookup", url: `https://vulnerability.circl.lu/vuln/${id.toLowerCase()}`, note: "Agrège NVD, EUVD, CSAF…" },
    { name: "Exploit-DB", url: `https://www.exploit-db.com/search?cve=${year}`, note: "Codes d'exploitation publics" },
  );
  return links;
}

export function cweLink(cwe: string): string | null {
  const m = /^CWE-(\d+)$/.exec(cwe);
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null;
}

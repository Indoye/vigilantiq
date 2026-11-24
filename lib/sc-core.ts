/**
 * SecurityContext (ProjectDiscovery) — fonctions pures : lecture des réponses de l'API en objets
 * compacts pour l'interface, et validation des noms de dépôts. Sans accès réseau ni base (testables).
 * Référence : https://securitycontext.com/docs
 */

export type ScSeverity = "critical" | "high" | "medium" | "low" | "none" | "unrated";

/** owner/name à partir de « owner/name », « github.com/owner/name » ou d'une URL GitHub. */
export function parseRepo(input: string): string | null {
  const s = input
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/^(www\.)?github\.com\//i, "")
    .replace(/\/+$/, "")
    .replace(/\.git$/i, "");
  const m = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/.exec(s);
  if (!m || m[2] === "." || m[2] === "..") return null;
  return `${m[1]}/${m[2]}`;
}

export const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

// ---------- CVE ----------

export interface ScCve {
  id: string;
  name: string | null;
  impact: string | null;
  remediation: string | null;
  severity: string | null;
  patchAvailable: boolean | null;
  exploitation: {
    knownExploited: boolean;
    by: string[];
    cisaSince: string | null;
    vulncheckSince: string | null;
    ransomware: boolean;
    publicExploit: boolean;
    publicExploits: number;
    publicExploitsCapped: boolean;
    firstExploit: string | null;
    initialAccess: boolean;
    remote: boolean | null;
    authRequired: boolean | null;
    exposedHosts: number | null;
    hackerone: number | null;
  };
  nuclei: { id: string; url: string } | null;
  exploits: { url: string; date: string | null }[];
  products: { product: string; affected: string[] }[];
  productsTotal: number;
  projects: string[];
  exposure: { repositories: number; packages: number };
  dataset: string | null;
}

type J = Record<string, unknown>;
const arr = (v: unknown): J[] => (Array.isArray(v) ? (v as J[]) : []);
const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);

/** Réponse de GET /v1/cves/{id} → résumé affichable. */
export function readCve(j: J): ScCve | null {
  if (!j || j.found === false || typeof j.cve !== "string") return null;
  const ex = (j.exploitation ?? {}) as J;
  const kev = arr(j.known_exploited_entries);
  const cisa = kev.find((k) => k.list === "cisa");
  const nuclei = arr(j.nuclei_templates)[0] ?? (ex.nuclei_template as J | null) ?? null;
  const index = (j.index ?? {}) as J;
  return {
    id: j.cve,
    name: str(j.name),
    impact: str(j.impact),
    remediation: str(j.remediation),
    severity: str(j.severity),
    patchAvailable: bool(j.patch_available),
    exploitation: {
      knownExploited: ex.known_exploited === true,
      by: Array.isArray(ex.known_exploited_by) ? (ex.known_exploited_by as string[]) : [],
      cisaSince: str(cisa?.added_date) ?? str(ex.known_exploited_since),
      vulncheckSince: str(ex.vulncheck_known_exploited_since),
      ransomware: kev.some((k) => k.ransomware_use === true),
      publicExploit: ex.public_exploit === true,
      publicExploits: num(j.public_exploits_total) ?? num(ex.public_exploit_count) ?? 0,
      publicExploitsCapped: j.public_exploits_capped === true,
      firstExploit: str(ex.public_exploit_first_date),
      initialAccess: ex.initial_access === true,
      remote: bool(ex.remote),
      authRequired: bool(ex.authentication_required),
      exposedHosts: num(ex.exposed_hosts),
      hackerone: num(ex.hackerone_reports),
    },
    nuclei: nuclei && str(nuclei.url) ? { id: String(nuclei.id ?? j.cve), url: String(nuclei.url) } : null,
    exploits: arr(j.public_exploits)
      .slice(0, 5)
      .map((e) => ({ url: String(e.url ?? ""), date: str(e.added_date) }))
      .filter((e) => /^https?:\/\//.test(e.url)),
    products: arr(j.products)
      .slice(0, 12)
      .map((p) => ({ product: String(p.product ?? ""), affected: (Array.isArray(p.affected) ? (p.affected as string[]) : []).slice(0, 6) })),
    productsTotal: num(j.products_total) ?? arr(j.products).length,
    projects: arr(j.projects)
      .map((p) => str(p.repository))
      .filter((x): x is string => Boolean(x))
      .slice(0, 8),
    exposure: { repositories: num(index.repositories) ?? 0, packages: num(index.packages) ?? 0 },
    dataset: str(((j._meta ?? {}) as J).dataset),
  };
}

// ---------- Flux des escalades ----------

export const ESCALATION_KINDS = ["known_exploited", "vulncheck_known_exploited", "initial_access_published", "public_exploit", "nuclei_template", "raised_to_critical"] as const;
export type EscalationKind = (typeof ESCALATION_KINDS)[number];

export const ESCALATION_FR: Record<EscalationKind, string> = {
  known_exploited: "Exploitée (CISA KEV)",
  vulncheck_known_exploited: "Exploitée (VulnCheck)",
  initial_access_published: "Accès initial",
  public_exploit: "Exploit public",
  nuclei_template: "Détectable (Nuclei)",
  raised_to_critical: "Passée critique",
};

export interface Escalation {
  cve: string;
  kind: EscalationKind;
  date: string;
  severity: string | null;
  summary: string;
}

/** Flux JSON Feed 1.1 de /v1/feed → escalades (une par CVE, type et jour). */
export function readFeed(j: J): Escalation[] {
  const out: Escalation[] = [];
  for (const it of arr(j.items)) {
    const m = /\/cves\/(CVE-\d{4}-\d{4,7})#([a-z_]+):/.exec(String(it.id ?? ""));
    if (!m) continue;
    const kind = m[2] as EscalationKind;
    if (!ESCALATION_KINDS.includes(kind)) continue;
    const tags = Array.isArray(it.tags) ? (it.tags as string[]) : [];
    const sev = tags.find((t) => ["critical", "high", "medium", "low"].includes(t)) ?? null;
    out.push({ cve: m[1], kind, date: String(it.date_published ?? "").slice(0, 10), severity: sev, summary: String(it.content_text ?? "").slice(0, 400) });
  }
  return out;
}

/** Escalades regroupées par CVE (types les plus graves d'abord). */
export function escalationsByCve(list: Escalation[]): Record<string, EscalationKind[]> {
  const out: Record<string, EscalationKind[]> = {};
  for (const e of list) {
    const k = (out[e.cve] ??= []);
    if (!k.includes(e.kind)) k.push(e.kind);
  }
  for (const k of Object.values(out)) k.sort((a, b) => ESCALATION_KINDS.indexOf(a) - ESCALATION_KINDS.indexOf(b));
  return out;
}

// ---------- Dépôts de code ----------

export interface ScUpgrade {
  manifest: string;
  direct: string | null;
  affected: number;
  worst: string | null;
  packages: { input: string; fixed: string | null; worst: string | null }[];
}

export interface ScRepoView {
  repo: string;
  found: boolean;
  candidates: string[];
  riskScore: number | null;
  percentile: number | null;
  severity: string | null;
  stars: number | null;
  lastPush: string | null;
  scan: string | null;
  counts: { vulnerableRuntime: number; publicExploit: number; reportedExploited: number; activeSecrets: number; contributorsWithLeak: number; libraries: number };
  cheapestPath: { type: string; detail: string; fix: string } | null;
  entryPoints: { type: string; count: number; fix: string }[];
  breakdown: Record<string, number>;
  stack: { packages: number; affected: number; knownExploited: number; publicExploit: number; malicious: number; bySeverity: Record<string, number> } | null;
  upgrades: ScUpgrade[];
  dataset: string | null;
}

/** GET /v1/repositories/{repo} + /risk + /stack?status=affected → vue compacte. */
export function readRepo(repo: string, main: J | null, risk: J | null, stack: J | null): ScRepoView {
  const counts = (main?.counts ?? {}) as J;
  const r = (risk?.risk ?? {}) as J;
  const cp = (r.cheapest_path ?? null) as J | null;
  const sum = (stack?.summary ?? null) as J | null;
  const groups = arr(((stack?.groups ?? {}) as J).items);
  return {
    repo,
    found: Boolean(main && main.found !== false),
    candidates: arr(main?.candidates).map((c) => String(c.repository ?? c.name ?? c)).slice(0, 5),
    riskScore: num(main?.risk_score) ?? num(risk?.risk_score),
    percentile: num(main?.risk_percentile) ?? num(risk?.risk_percentile),
    severity: str(main?.severity) ?? str(risk?.severity),
    stars: num(main?.stars),
    lastPush: str(main?.last_pushed_at),
    scan: str(main?.dependency_scan),
    counts: {
      vulnerableRuntime: num(counts.vulnerable_dependencies_runtime) ?? 0,
      publicExploit: num(counts.public_exploit_vulns) ?? 0,
      reportedExploited: num(counts.reported_exploited_vulns) ?? 0,
      activeSecrets: num(counts.active_secret_leaks) ?? 0,
      contributorsWithLeak: num(counts.contributors_with_leak) ?? 0,
      libraries: num(counts.libraries) ?? 0,
    },
    cheapestPath: cp ? { type: String(cp.type ?? ""), detail: String(cp.detail ?? ""), fix: String(cp.fix ?? "") } : null,
    entryPoints: arr(r.entry_points)
      .slice(0, 5)
      .map((e) => ({ type: String(e.type ?? ""), count: num(e.count) ?? 0, fix: String(e.fix ?? "") })),
    breakdown: Object.fromEntries(Object.entries((r.breakdown ?? {}) as J).filter(([, v]) => typeof v === "number")) as Record<string, number>,
    stack: sum
      ? {
          packages: num(sum.packages) ?? 0,
          affected: num(sum.affected) ?? 0,
          knownExploited: num(sum.known_exploited) ?? 0,
          publicExploit: num(sum.public_exploit) ?? 0,
          malicious: num(sum.malicious) ?? 0,
          bySeverity: (sum.by_severity ?? {}) as Record<string, number>,
        }
      : null,
    upgrades: groups
      .slice()
      .sort((a, b) => sevRank(str(b.worst_severity)) - sevRank(str(a.worst_severity)) || (num(b.affected) ?? 0) - (num(a.affected) ?? 0))
      .slice(0, 12)
      .map((g) => {
        const d = (g.direct_dependency ?? null) as J | null;
        return {
          manifest: String(g.manifest ?? ""),
          direct: d ? `${d.package}@${d.version}` : null,
          affected: num(g.affected) ?? 0,
          worst: str(g.worst_severity),
          packages: arr(g.packages)
            .filter((p) => p.status === "affected")
            .slice(0, 8)
            .map((p) => ({ input: String(p.input ?? ""), fixed: str(p.fixed_version), worst: str(p.worst_severity) })),
        };
      }),
    dataset: str(((main?._meta ?? risk?._meta ?? {}) as J).dataset),
  };
}

export function sevRank(s: string | null | undefined): number {
  return { critical: 4, high: 3, medium: 2, low: 1 }[s ?? ""] ?? 0;
}

export const SEVERITY_FR: Record<string, string> = { critical: "Critique", high: "Haute", medium: "Moyenne", low: "Basse", none: "Aucune", unrated: "Non notée" };

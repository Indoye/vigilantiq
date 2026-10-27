import type { AffectedProduct } from "./types.ts";

/* eslint-disable @typescript-eslint/no-explicit-any */

const MAX_RANGES = 14;

function clean(v: unknown): string | null {
  if (v == null) return null;
  const s = String(v).trim().replace(/\\(.)/g, "$1");
  if (!s || s === "*" || s === "-" || s.toLowerCase() === "n/a" || s.toLowerCase() === "unspecified") return null;
  return s;
}

function isZero(v: string | null): boolean {
  return v == null || v === "0" || v === "0.0" || v === "0.0.0";
}

export interface RangeParts {
  exact?: string | null;
  from?: string | null;
  fromExcl?: boolean;
  to?: string | null;
  toIncl?: boolean;
}

/** Plage lisible : « 7.0.0 → 7.0.13 », « 7.0.0 → < 7.0.14 », « ≤ 7.0.13 », « ≥ 3.1 », « 4.2.0 ». */
export function formatRange(r: RangeParts): string {
  if (r.exact) return r.exact;
  const from = isZero(r.from ?? null) ? null : r.from!;
  const to = r.to ?? null;
  const fromTxt = from ? (r.fromExcl ? `> ${from}` : from) : null;
  if (fromTxt && to) return `${fromTxt} → ${r.toIncl ? "" : "< "}${to}`;
  if (to) return `${r.toIncl ? "≤" : "<"} ${to}`;
  if (fromTxt) return r.fromExcl ? fromTxt : `≥ ${fromTxt}`;
  return "Toutes les versions";
}

/** ">= 1.0.0, < 1.4.2" → { from: "1.0.0", to: "1.4.2" } ; null si ce n'est pas une contrainte. */
export function parseConstraint(s: string): RangeParts | null {
  if (!/[<>]/.test(s)) return null;
  const r: RangeParts = {};
  for (const tok of s.split(",").map((t) => t.trim()).filter(Boolean)) {
    const m = /^(>=|>|<=|<|=)?\s*(\S+)$/.exec(tok);
    if (!m) return null;
    const [, op = "=", ver] = m;
    if (op === ">=" || op === ">") {
      r.from = ver;
      r.fromExcl = op === ">";
    } else if (op === "<=" || op === "<") {
      r.to = ver;
      r.toIncl = op === "<=";
    } else r.exact = ver;
  }
  return r;
}

function key(vendor: string, product: string) {
  return `${vendor.toLowerCase()}::${product.toLowerCase()}`;
}

function push<T>(arr: T[], v: T) {
  if (!arr.includes(v) && arr.length < MAX_RANGES) arr.push(v);
}

function pretty(name: string): string {
  return name.replace(/_/g, " ");
}

// ---------- NVD (configurations / cpeMatch) ----------

export function nvdAffected(configurations: any[] | undefined): AffectedProduct[] {
  const map = new Map<string, AffectedProduct>();
  const platforms: string[] = [];
  for (const conf of configurations ?? []) {
    for (const node of conf.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        const parts = String(m.criteria ?? "").split(":");
        if (parts.length < 6) continue;
        const vendor = clean(parts[3]) ?? "";
        const product = clean(parts[4]) ?? "";
        if (!product) continue;
        if (m.vulnerable === false) {
          const v = clean(parts[5]);
          push(platforms, pretty(product) + (v ? ` ${v}` : ""));
          continue;
        }
        const k = key(vendor, product);
        if (!map.has(k)) {
          map.set(k, { source: "NVD", vendor: pretty(vendor), product: pretty(product), ranges: [], fixed: [], platforms: [] });
        }
        const ap = map.get(k)!;
        const hasRange =
          m.versionStartIncluding || m.versionStartExcluding || m.versionEndIncluding || m.versionEndExcluding;
        const exact = clean(parts[5]);
        const update = clean(parts[6]);
        if (!hasRange && exact) {
          push(ap.ranges, update ? `${exact} ${update}` : exact);
        } else {
          push(
            ap.ranges,
            formatRange({
              from: clean(m.versionStartIncluding) ?? clean(m.versionStartExcluding),
              fromExcl: Boolean(m.versionStartExcluding),
              to: clean(m.versionEndIncluding) ?? clean(m.versionEndExcluding),
              toIncl: Boolean(m.versionEndIncluding),
            }),
          );
          const fix = clean(m.versionEndExcluding);
          if (fix) push(ap.fixed, fix);
        }
      }
    }
  }
  const out = [...map.values()];
  if (platforms.length) for (const ap of out) ap.platforms = platforms.slice(0, 6);
  return out;
}

// ---------- CVE.org (enregistrement CVE JSON 5, conteneur CNA) ----------

export function cnaAffected(record: any): AffectedProduct[] {
  const affected: any[] = record?.containers?.cna?.affected ?? [];
  const out: AffectedProduct[] = [];
  for (const a of affected) {
    const product = clean(a.product) ?? clean(a.packageName);
    if (!product) continue;
    const ap: AffectedProduct = {
      source: "CNA",
      vendor: clean(a.vendor) ?? "",
      product,
      ranges: [],
      fixed: [],
      platforms: (a.platforms ?? []).map(String).slice(0, 6),
    };
    if (a.collectionURL && a.packageName) ap.ecosystem = String(a.collectionURL).replace(/^https?:\/\//, "");
    for (const v of a.versions ?? []) {
      const version = clean(v.version);
      // Format « ecosystem » de GitHub et d'autres CNA : ">= 1.0.0, < 1.4.2"
      const expr = version ? parseConstraint(version) : null;
      if (expr && v.status === "affected") {
        push(ap.ranges, formatRange(expr));
        if (expr.to && !expr.toIncl) push(ap.fixed, expr.to);
        continue;
      }
      const lt = v.lessThan === "*" ? null : clean(v.lessThan);
      const lte = clean(v.lessThanOrEqual);
      if (v.status === "unaffected") {
        // « non affectée à partir de X » = version corrective
        if (version && !isZero(version)) push(ap.fixed, version);
        continue;
      }
      if (v.status !== "affected") continue;
      if (lt || lte) {
        push(ap.ranges, formatRange({ from: version, to: lt ?? lte, toIncl: !lt }));
        if (lt) push(ap.fixed, lt);
      } else if (v.lessThan === "*") {
        push(ap.ranges, formatRange({ from: version }));
      } else if (version) {
        push(ap.ranges, version);
      }
    }
    if (ap.ranges.length === 0 && a.defaultStatus === "affected") ap.ranges.push("Toutes les versions");
    if (ap.ranges.length || ap.fixed.length) out.push(ap);
  }
  return out;
}

// ---------- OSV (paquets open source) ----------

export function osvAffected(osv: any): AffectedProduct[] {
  const out: AffectedProduct[] = [];
  for (const a of osv?.affected ?? []) {
    const name = clean(a.package?.name);
    if (!name) continue;
    const ap: AffectedProduct = {
      source: "OSV",
      vendor: "",
      product: name,
      ecosystem: clean(a.package?.ecosystem) ?? undefined,
      ranges: [],
      fixed: [],
      platforms: [],
    };
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      let start: string | null = null;
      for (const e of r.events ?? []) {
        if (e.introduced != null) start = String(e.introduced);
        else if (e.fixed != null) {
          push(ap.ranges, formatRange({ from: start, to: String(e.fixed) }));
          push(ap.fixed, String(e.fixed));
          start = null;
        } else if (e.last_affected != null) {
          push(ap.ranges, formatRange({ from: start, to: String(e.last_affected), toIncl: true }));
          start = null;
        }
      }
      if (start != null) push(ap.ranges, formatRange({ from: start }));
    }
    if (ap.ranges.length === 0 && Array.isArray(a.versions) && a.versions.length) {
      a.versions.slice(0, MAX_RANGES).forEach((v: string) => push(ap.ranges, v));
    }
    if (ap.ranges.length || ap.fixed.length) out.push(ap);
  }
  return out;
}

/** Une ligne courte pour les listes et le digest : « FortiOS 7.0.0 → 7.0.13, 7.2.0 → 7.2.5 ». */
export function affectedSummary(list: AffectedProduct[], max = 2): string {
  return list
    .slice(0, max)
    .map((a) => `${a.product} ${a.ranges.slice(0, 2).join(", ")}${a.ranges.length > 2 ? "…" : ""}`.trim())
    .join(" ; ");
}

/** Préfère l'éditeur (CNA) puis NVD puis OSV, sans doublons de produit. */
export function mergeAffected(...lists: AffectedProduct[][]): AffectedProduct[] {
  const seen = new Set<string>();
  const out: AffectedProduct[] = [];
  for (const list of lists) {
    for (const a of list) {
      const k = `${a.source}::${a.product.toLowerCase()}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(a);
    }
  }
  return out;
}

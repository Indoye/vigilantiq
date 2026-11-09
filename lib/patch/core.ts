/**
 * Parc & correctifs — logique pure (sans base ni réseau) : clés d'enrôlement et d'équipement, signature des tâches,
 * lecture de l'inventaire envoyé par l'agent, comparaison de versions, correspondance avec la NVD (CPE) et OSV
 * (paquets Linux), score CVSS 3.x et score de priorité VigilantIQ.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { priorityFor, scoreVuln } from "../score.ts";
import type { Priority } from "../types.ts";

/** Version de l'agent distribuée par le serveur : un agent plus ancien se met à jour à sa prochaine synchronisation. */
export const AGENT_VERSION = "1.0.0";

export const LIMITS = { bodyBytes: 6_000_000, apps: 3000, packages: 25000, kbs: 1500, drivers: 600, logChars: 20_000 };

// ---------- Clés ----------

type KeyKind = "vqe" | "vqd";
const LABEL: Record<KeyKind, string> = { vqe: "patch-enroll", vqd: "patch-device" };
const sig = (kind: KeyKind, secret: string, id: number, salt: string) => createHmac("sha256", secret).update(`${LABEL[kind]}:${id}:${salt}`).digest("base64url").slice(0, 32);
export const newSalt = () => randomBytes(9).toString("base64url");
const makeKey = (kind: KeyKind, secret: string, id: number, salt: string) => `${kind}_${id}_${salt}_${sig(kind, secret, id, salt)}`;
function parseKey(kind: KeyKind, k: string): { id: number; salt: string; sig: string } | null {
  const m = new RegExp(`^${kind}_(\\d{1,9})_([A-Za-z0-9_-]{12})_([A-Za-z0-9_-]{32})$`).exec(k.trim());
  return m ? { id: Number(m[1]), salt: m[2], sig: m[3] } : null;
}
function keyMatches(kind: KeyKind, secret: string, k: string, salt: string | null): boolean {
  const p = parseKey(kind, k);
  if (!p || !salt || p.salt !== salt) return false;
  const want = sig(kind, secret, p.id, salt);
  return want.length === p.sig.length && timingSafeEqual(Buffer.from(want), Buffer.from(p.sig));
}

/** Jeton d'enrôlement (un par utilisateur), intégré à l'installeur de l'agent. */
export const enrollToken = (secret: string, id: number, salt: string) => makeKey("vqe", secret, id, salt);
export const parseEnrollToken = (k: string) => parseKey("vqe", k);
export const enrollTokenMatches = (secret: string, k: string, salt: string | null) => keyMatches("vqe", secret, k, salt);

/** Clé propre à un équipement, remise à l'agent lors de l'enrôlement et jamais stockée. */
export const deviceKey = (secret: string, id: number, salt: string) => makeKey("vqd", secret, id, salt);
export const parseDeviceKey = (k: string) => parseKey("vqd", k);
export const deviceKeyMatches = (secret: string, k: string, salt: string | null) => keyMatches("vqd", secret, k, salt);

/**
 * Signature d'une tâche : l'agent n'exécute que ce qui est signé avec la clé de son équipement.
 * La charge est transmise sous forme de texte JSON, signé tel quel (pas de sérialisation à reproduire côté agent).
 */
export const signJob = (key: string, id: number, action: string, payloadJson: string) => createHmac("sha256", key).update(`${id}.${action}.${payloadJson}`).digest("hex");
/** Signature d'une nouvelle version du script de l'agent. */
export const signScript = (key: string, script: string) => createHmac("sha256", key).update(`script.${script}`).digest("hex");

// ---------- Inventaire ----------

export type OsFamily = "windows" | "linux" | "macos";

export interface OsInfo {
  family: OsFamily;
  name: string;
  /** Windows : 10.0.<build>.<UBR> ; Linux : VERSION_ID */
  version: string;
  build: number | null;
  ubr: number | null;
  displayVersion: string;
  arch: string;
  server: boolean;
  /** Linux : identifiant de la distribution (debian, ubuntu, rocky…) */
  distro: string;
  distroLike: string;
  kernel: string;
  /** deb | rpm | "" */
  pkg: string;
}

export interface Component {
  kind: "os" | "kb" | "app" | "package" | "driver" | "bios";
  name: string;
  vendor: string;
  version: string;
  source: string;
  extra: Record<string, string>;
}

export interface Inventory {
  hostname: string;
  ip: string | null;
  domain: string;
  loggedUser: string;
  rebootPending: boolean;
  appManager: boolean;
  os: OsInfo;
  hardware: Record<string, string>;
  components: Component[];
}

const clip = (s: unknown, n = 200) =>
  String(s ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, n);
const arr = (v: unknown): Record<string, unknown>[] => (Array.isArray(v) ? v.filter((x): x is Record<string, unknown> => Boolean(x) && typeof x === "object") : []);
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function normArch(a: string): string {
  const s = a.toLowerCase();
  if (/arm64|aarch64/.test(s)) return "arm64";
  if (/x64|amd64|x86_64|64-bit|64 bits/.test(s)) return "x64";
  if (/x86|i[3-6]86|32-bit|32 bits/.test(s)) return "x86";
  return s.slice(0, 20);
}

/** Lit et borne l'inventaire envoyé par l'agent (JSON). Tout champ inattendu est ignoré. */
export function parseInventory(raw: unknown): Inventory {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const o = (r.os && typeof r.os === "object" ? r.os : {}) as Record<string, unknown>;
  const family: OsFamily = o.family === "windows" ? "windows" : o.family === "macos" ? "macos" : "linux";
  const build = Number(o.build);
  const ubr = Number(o.ubr);
  const productType = Number(o.productType);
  const os: OsInfo = {
    family,
    name: clip(o.name, 120),
    version: clip(o.version, 60),
    build: Number.isInteger(build) && build > 0 ? build : null,
    ubr: Number.isInteger(ubr) && ubr >= 0 ? ubr : null,
    displayVersion: clip(o.displayVersion, 20),
    arch: normArch(clip(o.arch, 40)),
    server: family === "windows" ? productType === 2 || productType === 3 || /server/i.test(String(o.name ?? "")) : family === "macos" ? false : o.desktop !== true,
    distro: clip(o.id, 30).toLowerCase(),
    distroLike: clip(o.idLike, 60).toLowerCase(),
    kernel: clip(o.kernel, 80),
    pkg: o.pkg === "deb" || o.pkg === "rpm" ? o.pkg : "",
  };
  if (family === "windows" && os.build && !os.version) os.version = `10.0.${os.build}${os.ubr != null ? `.${os.ubr}` : ""}`;

  const hw = (r.hardware && typeof r.hardware === "object" ? r.hardware : {}) as Record<string, unknown>;
  const hardware: Record<string, string> = {};
  for (const k of ["manufacturer", "model", "serial", "biosVendor", "biosVersion", "biosDate", "cpu", "ramMb"]) {
    const v = clip(hw[k], 120);
    if (v) hardware[k] = v;
  }

  const macBuild = family === "macos" ? clip(o.macBuild, 20) : "";
  const pending = family === "macos" ? arr(r.pendingUpdates).slice(0, 30).map((u) => clip(u.title, 80) + (u.version ? ` ${clip(u.version, 20)}` : "")).filter(Boolean) : [];
  const components: Component[] = [
    {
      kind: "os",
      name: os.name || (family === "windows" ? "Windows" : family === "macos" ? "macOS" : "Linux"),
      vendor: family === "windows" ? "Microsoft" : family === "macos" ? "Apple" : os.distro,
      version: os.version,
      source: "",
      extra: {
        arch: os.arch,
        ...(os.displayVersion ? { displayVersion: os.displayVersion } : {}),
        ...(os.kernel ? { kernel: os.kernel } : {}),
        ...(macBuild ? { build: macBuild } : {}),
        ...(pending.length ? { pendingUpdates: pending.join(" ; ").slice(0, 600) } : {}),
      },
    },
  ];
  const seen = new Set<string>();
  const add = (c: Component) => {
    const k = `${c.kind}|${c.name.toLowerCase()}|${c.version}|${c.extra.arch ?? ""}`;
    if (!c.name || seen.has(k)) return;
    seen.add(k);
    components.push(c);
  };
  for (const k of arr(r.kbs).slice(0, LIMITS.kbs)) {
    const id = clip(k.id, 20).toUpperCase();
    if (/^KB\d{6,8}$/.test(id)) add({ kind: "kb", name: id, vendor: "Microsoft", version: "", source: "", extra: k.installedOn ? { installedOn: clip(k.installedOn, 30) } : {} });
  }
  // macOS : applications gérées par Homebrew (cask) reconnues par leur nom, formules ajoutées comme logiciels
  const brew = family === "macos" ? arr(r.brew).slice(0, 1500).filter((b) => /^[A-Za-z0-9@._+-]{1,100}$/.test(String(b.name ?? ""))) : [];
  const caskOf = new Map<string, string>();
  for (const b of brew) if (b.kind === "cask") caskOf.set(String(b.name).toLowerCase().replace(/-/g, " ").replace(/@.*$/, ""), String(b.name));
  const usedCasks = new Set<string>();
  for (const a of arr(r.apps).slice(0, LIMITS.apps)) {
    const name = clip(a.name, 160);
    const token = caskOf.get(name.toLowerCase().replace(/[-_.]+/g, " ").trim());
    if (token) usedCasks.add(token);
    add({ kind: "app", name, vendor: clip(a.publisher, 120), version: clip(a.version, 60), source: "", extra: { ...(a.arch ? { arch: clip(a.arch, 10) } : {}), ...(token ? { brew: "cask", brewName: token } : {}) } });
  }
  for (const b of brew) {
    const name = String(b.name);
    if (b.kind === "cask" && usedCasks.has(name)) continue;
    add({ kind: "app", name, vendor: "Homebrew", version: clip(b.version, 60), source: "", extra: { brew: b.kind === "cask" ? "cask" : "formula", brewName: name } });
  }
  for (const p of arr(r.packages).slice(0, LIMITS.packages)) {
    const name = clip(p.name, 120);
    add({ kind: "package", name, vendor: "", version: clip(p.version, 80), source: clip(p.source, 120) || name, extra: { ...(p.sourceVersion ? { sourceVersion: clip(p.sourceVersion, 80) } : {}), ...(p.arch ? { arch: clip(p.arch, 20) } : {}) } });
  }
  for (const d of arr(r.drivers).slice(0, LIMITS.drivers)) add({ kind: "driver", name: clip(d.name, 160), vendor: clip(d.provider, 120), version: clip(d.version, 60), source: "", extra: d.date ? { date: clip(d.date, 30) } : {} });
  if (hardware.biosVersion) add({ kind: "bios", name: [hardware.manufacturer, hardware.model].filter(Boolean).join(" ") || "BIOS", vendor: hardware.biosVendor ?? hardware.manufacturer ?? "", version: hardware.biosVersion, source: "", extra: hardware.biosDate ? { date: hardware.biosDate } : {} });

  const ip = clip(r.ip, 45);
  return {
    hostname: clip(r.hostname, 80),
    ip: IPV4.test(ip) || /^[0-9a-f:]{2,39}$/i.test(ip) ? ip : null,
    domain: clip(r.domain, 120),
    loggedUser: clip(r.user, 120),
    rebootPending: r.rebootPending === true,
    appManager: r.appManager === true,
    os,
    hardware,
    components,
  };
}

// ---------- Comparaison de versions ----------

function tokens(v: string): (number | string)[] {
  const out: (number | string)[] = [];
  for (const part of v.toLowerCase().split(/[^0-9a-z]+/)) {
    for (const t of part.match(/\d+|[a-z]+/g) ?? []) out.push(/^\d+$/.test(t) ? Number(t) : t);
  }
  return out;
}

/**
 * Compare deux versions « éditeur » (1.2.10 > 1.2.9, 10.0.19045.4529, 24.08). Un suffixe alphabétique
 * (beta, rc) passe avant la version finale. Renvoie -1, 0 ou 1.
 */
export function cmpVersion(a: string, b: string): number {
  const x = tokens(a);
  const y = tokens(b);
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const p = x[i];
    const q = y[i];
    if (p === undefined) return typeof q === "string" ? 1 : (q as number) > 0 ? -1 : 0;
    if (q === undefined) return typeof p === "string" ? -1 : p > 0 ? 1 : 0;
    if (typeof p === "number" && typeof q === "number") {
      if (p !== q) return p < q ? -1 : 1;
    } else if (typeof p === "string" && typeof q === "string") {
      if (p !== q) return p < q ? -1 : 1;
    } else return typeof p === "number" ? 1 : -1;
  }
  return 0;
}

// ---------- Windows → produit CPE de la NVD ----------

const WIN_CLIENT: Record<number, string> = {
  10240: "windows_10_1507",
  14393: "windows_10_1607",
  17763: "windows_10_1809",
  19044: "windows_10_21h2",
  19045: "windows_10_22h2",
  22000: "windows_11_21h2",
  22621: "windows_11_22h2",
  22631: "windows_11_23h2",
  26100: "windows_11_24h2",
  26200: "windows_11_25h2",
};
const WIN_SERVER: Record<number, string> = {
  14393: "windows_server_2016",
  17763: "windows_server_2019",
  20348: "windows_server_2022",
  25398: "windows_server_2022_23h2",
  26100: "windows_server_2025",
};

/** Produit NVD d'une version de Windows (par numéro de build), ou null si la version n'est pas suivie. */
export function windowsProduct(os: Pick<OsInfo, "family" | "build" | "server">): string | null {
  if (os.family !== "windows" || !os.build) return null;
  return (os.server ? WIN_SERVER[os.build] : WIN_CLIENT[os.build]) ?? null;
}

// ---------- NVD : correspondance par CPE ----------

/** Plage de versions vulnérables d'un critère CPE (forme compacte mise en cache). */
export interface CpeRange {
  criteria: string;
  vsi?: string;
  vse?: string;
  vei?: string;
  vee?: string;
}
export interface NvdCve {
  id: string;
  cvss: number | null;
  published: string;
  matches: CpeRange[];
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function nvdCvss(metrics: any): number | null {
  for (const k of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list = metrics?.[k];
    if (!Array.isArray(list) || !list.length) continue;
    const m = list.find((x: any) => x.type === "Primary") ?? list[0];
    const s = Number(m?.cvssData?.baseScore);
    if (Number.isFinite(s)) return s;
  }
  return null;
}

/** Réduit une fiche NVD 2.0 aux critères CPE d'un produit (éditeur:produit), pour la mise en cache. */
export function compactNvdItem(item: any, vendor: string, product: string): NvdCve | null {
  const c = item?.cve ?? item;
  if (!c?.id || c.vulnStatus === "Rejected") return null;
  const matches: CpeRange[] = [];
  for (const conf of c.configurations ?? []) {
    for (const node of conf.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (m.vulnerable === false) continue;
        const parts = String(m.criteria ?? "").split(":");
        if (parts[3] !== vendor || parts[4] !== product) continue;
        const r: CpeRange = { criteria: String(m.criteria) };
        if (m.versionStartIncluding) r.vsi = String(m.versionStartIncluding);
        if (m.versionStartExcluding) r.vse = String(m.versionStartExcluding);
        if (m.versionEndIncluding) r.vei = String(m.versionEndIncluding);
        if (m.versionEndExcluding) r.vee = String(m.versionEndExcluding);
        matches.push(r);
      }
    }
  }
  if (!matches.length) return null;
  return { id: String(c.id), cvss: nvdCvss(c.metrics), published: String(c.published ?? ""), matches };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

const anyField = (s: string | undefined) => s === undefined || s === "*" || s === "-" || s === "";

/** Une version installée est-elle dans la plage d'un critère CPE ? */
export function rangeMatches(r: CpeRange, version: string, arch = ""): boolean {
  const parts = r.criteria.split(":");
  const hw = parts[10];
  if (!anyField(hw) && arch && hw !== arch) return false;
  const hasRange = Boolean(r.vsi || r.vse || r.vei || r.vee);
  if (!hasRange) {
    const exact = parts[5];
    return anyField(exact) ? true : cmpVersion(version, exact.replace(/\\/g, "")) === 0;
  }
  if (r.vsi && cmpVersion(version, r.vsi) < 0) return false;
  if (r.vse && cmpVersion(version, r.vse) <= 0) return false;
  if (r.vei && cmpVersion(version, r.vei) > 0) return false;
  if (r.vee && cmpVersion(version, r.vee) >= 0) return false;
  return true;
}

export interface NvdHit {
  cveId: string;
  cvss: number | null;
  /** Première version qui corrige (fin de plage exclue), si la NVD la donne */
  fixedVersion: string | null;
}

/** CVE de la NVD qui touchent la version installée d'un produit. */
export function matchNvd(cves: NvdCve[], version: string, arch = ""): NvdHit[] {
  if (!version) return [];
  const out: NvdHit[] = [];
  for (const c of cves) {
    const hit = c.matches.find((r) => rangeMatches(r, version, arch));
    if (hit) out.push({ cveId: c.id, cvss: c.cvss, fixedVersion: hit.vee ?? null });
  }
  return out;
}

// ---------- OSV : paquets des distributions Linux ----------

/**
 * Écosystème OSV d'une distribution. RHEL et CentOS Stream sont rapprochées des avis AlmaLinux (mêmes paquets et
 * versions) : c'est une approximation, signalée dans l'interface.
 */
export function osvEcosystem(os: Pick<OsInfo, "family" | "distro" | "distroLike" | "version">): { ecosystem: string; approx: boolean } | null {
  if (os.family !== "linux") return null;
  const v = os.version.trim();
  const major = v.split(".")[0];
  switch (os.distro) {
    case "debian":
      return /^\d+$/.test(major) ? { ecosystem: `Debian:${major}`, approx: false } : null;
    case "ubuntu": {
      const m = /^(\d{2})\.(\d{2})$/.exec(v);
      if (!m) return null;
      const lts = Number(m[1]) % 2 === 0 && m[2] === "04";
      return { ecosystem: `Ubuntu:${v}${lts ? ":LTS" : ""}`, approx: false };
    }
    case "rocky":
      return /^\d+$/.test(major) ? { ecosystem: `Rocky Linux:${major}`, approx: false } : null;
    case "almalinux":
      return /^\d+$/.test(major) ? { ecosystem: `AlmaLinux:${major}`, approx: false } : null;
    case "rhel":
    case "centos":
      return /^\d+$/.test(major) ? { ecosystem: `AlmaLinux:${major}`, approx: true } : null;
    default:
      return null;
  }
}

export interface OsvQuery {
  package: { name: string; ecosystem: string };
  version: string;
}

/**
 * Requêtes « querybatch » d'OSV pour les paquets installés. Debian et Ubuntu publient leurs avis par paquet source :
 * on interroge chaque paquet source une fois, avec sa version. Les distributions RPM sont interrogées par paquet.
 * Renvoie aussi, pour chaque nom interrogé, les paquets binaires installés à mettre à jour.
 */
export function osvQueries(components: Component[], ecosystem: string, pkg: string): { queries: OsvQuery[]; binaries: Map<string, string[]>; versions: Map<string, string> } {
  const binaries = new Map<string, string[]>();
  const versions = new Map<string, string>();
  for (const c of components) {
    if (c.kind !== "package" || !c.version) continue;
    const name = pkg === "deb" ? c.source || c.name : c.name;
    const version = pkg === "deb" ? c.extra.sourceVersion || c.version : c.version;
    if (!versions.has(name)) versions.set(name, version);
    binaries.set(name, [...new Set([...(binaries.get(name) ?? []), c.name])]);
  }
  const queries = [...versions.entries()].map(([name, version]) => ({ package: { name, ecosystem }, version }));
  return { queries, binaries, versions };
}

/* eslint-disable @typescript-eslint/no-explicit-any */
/** CVE d'un avis OSV (identifiant, alias, « upstream ») et version corrigée du paquet dans l'écosystème. */
export function osvToCves(osv: any, ecosystem: string, pkgName: string): { cves: string[]; fixed: string | null; cvss: number | null } {
  const ids = [osv?.id, ...(osv?.aliases ?? []), ...(osv?.upstream ?? [])].map(String).filter((s) => /^CVE-\d{4}-\d{4,}$/.test(s));
  let fixed: string | null = null;
  for (const a of osv?.affected ?? []) {
    if (a?.package?.name !== pkgName || String(a?.package?.ecosystem ?? "") !== ecosystem) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed != null) fixed = String(e.fixed);
  }
  let cvss: number | null = null;
  for (const s of [...(osv?.severity ?? []), ...(osv?.affected ?? []).flatMap((a: any) => a?.severity ?? [])]) {
    if (/^CVSS_V3/.test(String(s?.type)) && typeof s.score === "string") {
      const v = cvss3Score(s.score);
      if (v != null) cvss = Math.max(cvss ?? 0, v);
    }
  }
  return { cves: [...new Set(ids)], fixed, cvss };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

// ---------- CVSS 3.x ----------

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;
function roundUp(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** Score de base CVSS 3.0/3.1 calculé depuis le vecteur (« CVSS:3.1/AV:N/AC:L/… »), ou null si illisible. */
export function cvss3Score(vector: string): number | null {
  const m = Object.fromEntries(
    vector
      .split("/")
      .slice(1)
      .map((p) => p.split(":") as [string, string]),
  ) as Record<string, string>;
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const av = W.AV[m.AV as keyof typeof W.AV];
  const ac = W.AC[m.AC as keyof typeof W.AC];
  const ui = W.UI[m.UI as keyof typeof W.UI];
  const c = W.CIA[m.C as keyof typeof W.CIA];
  const i = W.CIA[m.I as keyof typeof W.CIA];
  const a = W.CIA[m.A as keyof typeof W.CIA];
  const changed = m.S === "C";
  if (m.S !== "U" && !changed) return null;
  const pr = m.PR === "N" ? 0.85 : m.PR === "L" ? (changed ? 0.68 : 0.62) : m.PR === "H" ? (changed ? 0.5 : 0.27) : undefined;
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * av * ac * pr! * ui;
  return roundUp(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

// ---------- Score de priorité ----------

export interface ScoreFacts {
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  ransomware: boolean;
  /** Codes d'exploitation publics repérés par la veille VigilantIQ */
  pocs: number;
  /** Serveur : surface exposée plus large */
  server: boolean;
  /** CVSS absent parce que la source (avis de distribution) ne le fournit pas */
  cvssFromAdvisory?: boolean;
}

/** Score VigilantIQ d'une CVE sur un équipement : celui de la veille (CVSS, EPSS, KEV, PoC) + l'exposition. */
export function deviceScore(f: ScoreFacts): { score: number; priority: Priority; reasons: string[] } {
  const base = scoreVuln({
    cvss: f.cvss,
    epss: f.epss,
    kev: f.kev ? { name: "", dateAdded: "", dueDate: "", action: "", ransomware: f.ransomware } : null,
    exploitCount: f.pocs,
  });
  const reasons = base.reasons.map((r) => (r === "Score CVSS pas encore publié" && f.cvssFromAdvisory ? "CVSS non fourni par l’avis de la distribution" : r));
  let score = base.score;
  if (f.server) {
    score = Math.min(100, score + 5);
    reasons.push("Serveur : exposition plus large qu’un poste de travail");
  }
  return { score, priority: priorityFor(score, f.kev), reasons };
}

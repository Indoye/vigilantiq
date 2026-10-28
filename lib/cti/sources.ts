/**
 * Sources gratuites du renseignement sur les menaces. Uniquement des métadonnées : l'application ne visite pas
 * elle-même le dark web et ne télécharge aucune donnée volée.
 *
 * - ransomware.live : victimes revendiquées sur les sites de fuite des rançongiciels (dark web), sans clé.
 * - Have I Been Pwned : catalogue public des fuites de données, sans clé.
 * - Hudson Rock (Cavalier, outil OSINT gratuit) : postes infectés par des « infostealers » dont les identifiants
 *   circulent sur les marchés, forums et canaux Telegram, par domaine — chiffres agrégés uniquement.
 * - XposedOrNot : fuites contenant une adresse e-mail (l'adresse du compte de l'utilisateur), sans clé.
 * - IOC : abuse.ch Feodo Tracker et OpenPhish sans clé ; ThreatFox et URLhaus avec ABUSECH_AUTH_KEY (gratuite).
 */
const UA = "vigilantiq/0.3 (+https://vigilantiq.vercel.app)";
const T = 20000;

async function getJson(url: string, init: RequestInit = {}): Promise<unknown> {
  const res = await fetch(url, {
    ...init,
    headers: { "User-Agent": UA, Accept: "application/json", ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(T),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const str = (v: unknown) => (typeof v === "string" ? v.trim() : v == null ? "" : String(v));
const isoOrNull = (v: unknown) => {
  const s = str(v);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
};

// ---------- Domaines ----------

const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;
const SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "gouv", "ac", "edu", "gv", "or", "ne", "go", "mil"]);

/** « https://www.Exemple.SN/page » → « exemple.sn » ; null si ce n'est pas un nom de domaine valide. */
export function normalizeDomain(input: string): string | null {
  let s = input.trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, "").replace(/^www\./, "");
  s = s.split(/[/?#:@\s]/)[0].replace(/\.$/, "");
  return DOMAIN_RE.test(s) ? s : null;
}

/** Libellé de marque d'un domaine : « sonatel.sn » → « sonatel », « exemple.co.uk » → « exemple ». */
export function brandOf(domain: string): string {
  const parts = domain.split(".");
  if (parts.length >= 3 && SECOND_LEVEL.has(parts[parts.length - 2])) return parts[parts.length - 3];
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
}

export function normalizeBrand(input: string): string | null {
  const s = input.trim().toLowerCase().replace(/\s+/g, " ");
  return /^[\p{L}\p{N}][\p{L}\p{N} .&'-]{2,39}$/u.test(s) ? s : null;
}

export const hostOf = (url: string) => {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
};

// ---------- Rançongiciels (ransomware.live) ----------

export interface RansomVictim {
  id: string;
  victim: string;
  domain: string;
  group: string;
  country: string;
  sector: string;
  discovered: string | null;
  attackDate: string | null;
  url: string;
}

/** Garde les métadonnées ; on n'expose ni l'adresse .onion, ni le texte d'extorsion, ni les captures. */
export function parseRansomVictims(json: unknown): RansomVictim[] {
  const list = Array.isArray(json) ? (json as Record<string, unknown>[]) : [];
  const out: RansomVictim[] = [];
  for (const it of list) {
    const victim = str(it.victim ?? it.post_title);
    const group = str(it.group ?? it.group_name);
    if (!victim || !group) continue;
    const url = str(it.url);
    const discovered = isoOrNull(it.discovered);
    out.push({
      id: url || `${group}:${victim}`.toLowerCase(),
      victim: victim.slice(0, 160),
      domain: normalizeDomain(str(it.domain || it.website)) ?? "",
      group,
      country: /^[A-Za-z]{2}$/.test(str(it.country)) ? str(it.country).toUpperCase() : "",
      sector: str(it.activity).slice(0, 60),
      discovered,
      attackDate: isoOrNull(it.attackdate) ?? discovered,
      url: /^https:\/\/(www\.)?ransomware\.live\//.test(url) ? url : "",
    });
  }
  return out.sort((a, b) => (b.discovered ?? "").localeCompare(a.discovered ?? ""));
}

export async function fetchRansomVictims(): Promise<RansomVictim[]> {
  return parseRansomVictims(await getJson("https://api.ransomware.live/v2/recentvictims"));
}

// ---------- Fuites de données (Have I Been Pwned, catalogue public) ----------

export interface Breach {
  name: string;
  title: string;
  domain: string;
  breachDate: string | null;
  addedDate: string | null;
  pwnCount: number;
  dataClasses: string[];
  verified: boolean;
  stealerLog: boolean;
  description: string;
}

const stripHtml = (s: string) => s.replace(/<[^>]+>/g, "").replace(/&quot;/g, '"').replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/\s+/g, " ").trim();

export function parseBreaches(json: unknown): Breach[] {
  const list = Array.isArray(json) ? (json as Record<string, unknown>[]) : [];
  return list
    .filter((b) => str(b.Name) && b.IsSpamList !== true && b.IsFabricated !== true)
    .map((b) => ({
      name: str(b.Name),
      title: str(b.Title) || str(b.Name),
      domain: normalizeDomain(str(b.Domain)) ?? "",
      breachDate: str(b.BreachDate) || null,
      addedDate: isoOrNull(b.AddedDate),
      pwnCount: Number(b.PwnCount) || 0,
      dataClasses: Array.isArray(b.DataClasses) ? (b.DataClasses as unknown[]).map(str).slice(0, 12) : [],
      verified: b.IsVerified === true,
      stealerLog: b.IsStealerLog === true,
      description: stripHtml(str(b.Description)).slice(0, 400),
    }))
    .sort((a, b) => (b.addedDate ?? "").localeCompare(a.addedDate ?? ""));
}

export async function fetchBreaches(): Promise<Breach[]> {
  return parseBreaches(await getJson("https://haveibeenpwned.com/api/v3/breaches"));
}

// ---------- Infostealers par domaine (Hudson Rock, données agrégées) ----------

export interface InfostealerStats {
  domain: string;
  total: number;
  employees: number;
  users: number;
  thirdParties: number;
  lastEmployee: string | null;
  lastUser: string | null;
  families: { name: string; count: number }[];
  /** Applications internes exposées (noms d'hôte uniquement, jamais d'URL complète) */
  employeeHosts: { host: string; count: number }[];
  weakPasswordsPct: number | null;
}

export function parseInfostealer(domain: string, json: unknown): InfostealerStats {
  const j = (json ?? {}) as Record<string, unknown>;
  const data = (j.data ?? {}) as Record<string, unknown>;
  const hosts = new Map<string, number>();
  for (const u of Array.isArray(data.employees_urls) ? (data.employees_urls as Record<string, unknown>[]) : []) {
    const h = hostOf(str(u.url).replace(/^"+|"+,?$/g, ""));
    if (h) hosts.set(h, (hosts.get(h) ?? 0) + (Number(u.occurrence) || 1));
  }
  const fam = (j.stealerFamilies ?? {}) as Record<string, unknown>;
  const families = Object.entries(fam)
    .filter(([k]) => k !== "total" && k !== "UNKNOWN")
    .map(([name, v]) => ({ name, count: Number(v) || 0 }))
    .filter((f) => f.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
  const ep = (j.employeePasswords ?? {}) as Record<string, { perc?: number } | boolean | number>;
  const weak = ep.has_stats ? (Number((ep.too_weak as { perc?: number })?.perc) || 0) + (Number((ep.weak as { perc?: number })?.perc) || 0) : null;
  return {
    domain,
    total: Number(j.total) || 0,
    employees: Number(j.employees) || 0,
    users: Number(j.users) || 0,
    thirdParties: Number(j.third_parties) || 0,
    lastEmployee: isoOrNull(j.last_employee_compromised),
    lastUser: isoOrNull(j.last_user_compromised),
    families,
    employeeHosts: [...hosts.entries()].map(([host, count]) => ({ host, count })).sort((a, b) => b.count - a.count).slice(0, 8),
    weakPasswordsPct: weak == null ? null : Math.round(weak * 10) / 10,
  };
}

export async function fetchInfostealer(domain: string): Promise<InfostealerStats> {
  const json = await getJson(`https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`);
  return parseInfostealer(domain, json);
}

// ---------- Adresse e-mail dans des fuites (XposedOrNot) ----------

export function parseXposed(json: unknown): string[] {
  const j = (json ?? {}) as { breaches?: unknown };
  const b = Array.isArray(j.breaches) ? j.breaches.flat() : [];
  return [...new Set(b.map(str).filter(Boolean))];
}

export async function fetchEmailBreaches(email: string): Promise<string[]> {
  const res = await fetch(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, {
    headers: { "User-Agent": UA, Accept: "application/json" },
    signal: AbortSignal.timeout(T),
    cache: "no-store",
  });
  if (res.status === 404) return []; // adresse absente des fuites connues
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return parseXposed(await res.json());
}

// ---------- Indicateurs de compromission ----------

export type IocType = "ip:port" | "ip" | "domain" | "url" | "md5" | "sha1" | "sha256";

export interface Ioc {
  type: IocType;
  value: string;
  threat: string;
  malware: string;
  source: string;
  firstSeen: string | null;
  confidence: number | null;
  tags: string[];
  ref: string;
}

export function iocsFromFeodo(json: unknown): Ioc[] {
  const list = Array.isArray(json) ? (json as Record<string, unknown>[]) : [];
  return list
    .filter((it) => str(it.ip_address))
    .map((it) => ({
      type: (it.port ? "ip:port" : "ip") as IocType,
      value: it.port ? `${str(it.ip_address)}:${str(it.port)}` : str(it.ip_address),
      threat: "Serveur de commande (C2) de botnet",
      malware: str(it.malware) || "Inconnu",
      source: "abuse.ch Feodo Tracker",
      firstSeen: isoOrNull(str(it.first_seen).replace(" ", "T") + (str(it.first_seen) ? "Z" : "")),
      confidence: str(it.status).toLowerCase() === "online" ? 100 : 75,
      tags: [str(it.country), str(it.status).toLowerCase() === "online" ? "en ligne" : str(it.status) ? "hors ligne" : ""].filter(Boolean),
      ref: `https://feodotracker.abuse.ch/browse/host/${encodeURIComponent(str(it.ip_address))}/`,
    }));
}

export function iocsFromOpenPhish(text: string, fetchedAt: string): Ioc[] {
  const seen = new Set<string>();
  const out: Ioc[] = [];
  for (const line of text.split("\n")) {
    const u = line.trim();
    if (!/^https?:\/\//i.test(u) || u.length > 600 || seen.has(u)) continue;
    seen.add(u);
    out.push({ type: "url", value: u, threat: "Page d’hameçonnage", malware: "", source: "OpenPhish", firstSeen: fetchedAt, confidence: 80, tags: [hostOf(u)].filter(Boolean), ref: "https://openphish.com/" });
  }
  return out;
}

const TF_TYPES: Record<string, IocType> = { "ip:port": "ip:port", domain: "domain", url: "url", md5_hash: "md5", sha1_hash: "sha1", sha256_hash: "sha256" };

export function iocsFromThreatFox(json: unknown): Ioc[] {
  const data = ((json ?? {}) as { data?: unknown }).data;
  const list = Array.isArray(data) ? (data as Record<string, unknown>[]) : [];
  return list.flatMap((it) => {
    const type = TF_TYPES[str(it.ioc_type)];
    if (!type || !str(it.ioc)) return [];
    return [
      {
        type,
        value: str(it.ioc),
        threat: str(it.threat_type_desc) || str(it.threat_type),
        malware: str(it.malware_printable) || str(it.malware),
        source: "abuse.ch ThreatFox",
        firstSeen: isoOrNull(str(it.first_seen).replace(" UTC", "Z").replace(" ", "T")),
        confidence: Number(it.confidence_level) || null,
        tags: Array.isArray(it.tags) ? (it.tags as unknown[]).map(str).slice(0, 6) : [],
        ref: it.id ? `https://threatfox.abuse.ch/ioc/${str(it.id)}/` : "https://threatfox.abuse.ch/",
      },
    ];
  });
}

export function iocsFromUrlhaus(json: unknown): Ioc[] {
  const urls = ((json ?? {}) as { urls?: unknown }).urls;
  const list = Array.isArray(urls) ? (urls as Record<string, unknown>[]) : [];
  return list
    .filter((it) => str(it.url))
    .map((it) => ({
      type: "url" as IocType,
      value: str(it.url),
      threat: str(it.threat) === "malware_download" ? "Distribution de malware" : str(it.threat) || "URL malveillante",
      malware: "",
      source: "abuse.ch URLhaus",
      firstSeen: isoOrNull(str(it.date_added).replace(" UTC", "Z").replace(" ", "T")),
      confidence: str(it.url_status) === "online" ? 100 : 70,
      tags: Array.isArray(it.tags) ? (it.tags as unknown[]).map(str).slice(0, 6) : [],
      ref: str(it.urlhaus_reference) || "https://urlhaus.abuse.ch/",
    }));
}

export interface IocFeed {
  generatedAt: string;
  items: Ioc[];
  sources: { name: string; ok: boolean; count: number; note?: string }[];
}

export async function fetchIocs(): Promise<IocFeed> {
  const now = new Date().toISOString();
  const key = process.env.ABUSECH_AUTH_KEY?.trim();
  const tasks: [string, () => Promise<Ioc[]>][] = [
    ["abuse.ch Feodo Tracker", async () => iocsFromFeodo(await getJson("https://feodotracker.abuse.ch/downloads/ipblocklist.json"))],
    [
      "OpenPhish",
      async () => {
        const res = await fetch("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", {
          headers: { "User-Agent": UA },
          signal: AbortSignal.timeout(T),
          cache: "no-store",
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return iocsFromOpenPhish(await res.text(), now);
      },
    ],
  ];
  if (key) {
    tasks.push([
      "abuse.ch ThreatFox",
      async () =>
        iocsFromThreatFox(
          await getJson("https://threatfox-api.abuse.ch/api/v1/", {
            method: "POST",
            headers: { "Auth-Key": key, "Content-Type": "application/json" },
            body: JSON.stringify({ query: "get_iocs", days: 1 }),
          }),
        ),
    ]);
    tasks.push([
      "abuse.ch URLhaus",
      async () => iocsFromUrlhaus(await getJson("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/300/", { headers: { "Auth-Key": key } })),
    ]);
  }
  const results = await Promise.allSettled(tasks.map(([, f]) => f()));
  const items: Ioc[] = [];
  const sources: IocFeed["sources"] = results.map((r, i) => {
    if (r.status === "fulfilled") {
      items.push(...r.value);
      return { name: tasks[i][0], ok: true, count: r.value.length };
    }
    return { name: tasks[i][0], ok: false, count: 0, note: r.reason instanceof Error ? r.reason.message : String(r.reason) };
  });
  if (!key) {
    sources.push({ name: "abuse.ch ThreatFox et URLhaus", ok: false, count: 0, note: "ajoutez ABUSECH_AUTH_KEY (gratuite) pour les activer" });
  }
  const seen = new Set<string>();
  const dedup = items.filter((i) => {
    const k = `${i.type}|${i.value}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  dedup.sort((a, b) => (b.firstSeen ?? "").localeCompare(a.firstSeen ?? ""));
  return { generatedAt: now, items: dedup.slice(0, 3000), sources };
}


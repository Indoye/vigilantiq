/**
 * Fuites du darkweb — logique pure (sans base) : validation et minimisation des événements reçus,
 * empreintes, masquage, clés d'ingestion, score de gravité, domaines ressemblants, conversion MISP et STIX 2.1.
 *
 * Principe : rien de secret n'entre en base. Les mots de passe, cookies ou données personnelles reçus ne sont
 * conservés que sous forme d'indicateurs de présence (oui/non) ; les identifiants sont hachés (HMAC) et masqués.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { brandOf, normalizeDomain } from "./sources.ts";

// ---------- Référentiels (partagés avec l'interface) ----------

export * from "./leaklabels.ts";
import type { DataClass, IndicatorKind } from "./leaklabels.ts";

const CLASS_ALIASES: Record<string, DataClass> = {
  credential: "credentials", credentials: "credentials", logins: "credentials", login: "credentials", usernames: "credentials", combolist: "credentials", "combo-list": "credentials",
  password: "passwords", passwords: "passwords", hashes: "passwords", "password-hashes": "passwords",
  cookie: "cookies", cookies: "cookies", sessions: "cookies", tokens: "cookies",
  pii: "pii", personal: "pii", "personal-data": "pii", names: "pii", phones: "pii", addresses: "pii", "national-id": "pii", passports: "pii",
  financial: "financial", cards: "financial", "credit-cards": "financial", bank: "financial", iban: "financial",
  documents: "documents", files: "documents", database: "documents", "source-code": "documents",
  email: "emails", emails: "emails", "email-addresses": "emails",
};
export const normalizeClass = (c: string): DataClass => CLASS_ALIASES[c.trim().toLowerCase().replace(/[\s_]+/g, "-")] ?? "other";

// ---------- Empreintes et masquage ----------

/** Empreinte stable d'un identifiant (HMAC-SHA256 avec un secret serveur) : comparable, mais non réversible. */
export function keyedHash(pepper: string, kind: IndicatorKind, value: string): string {
  return createHmac("sha256", pepper).update(`${kind}:${value}`).digest("hex");
}

export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  const local = email.slice(0, at);
  const dom = email.slice(at + 1);
  const shown = local.length <= 2 ? local[0] : `${local[0]}${"•".repeat(Math.min(6, local.length - 2))}${local[local.length - 1]}`;
  return `${shown}@${dom}`;
}
export const maskUsername = (u: string) => (u.length <= 2 ? `${u[0]}•` : `${u[0]}${"•".repeat(Math.min(6, u.length - 2))}${u[u.length - 1]}`);
export function maskIp(ip: string): string {
  if (ip.includes(":")) return `${ip.split(":").slice(0, 2).join(":")}:•:•`;
  const p = ip.split(".");
  return `${p[0]}.${p[1]}.•.•`;
}

const EMAIL_RE = /^[a-z0-9._%+'-]+@([a-z0-9-]+\.)+[a-z]{2,}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^[0-9a-f:]{3,39}$/;

// ---------- Validation et minimisation ----------

export interface MinIndicator {
  kind: IndicatorKind;
  domain: string | null;
  valueHash: string;
  masked: string;
  hasPassword: boolean;
  hasCookie: boolean;
  hasPii: boolean;
}

export interface MinEvent {
  externalId: string | null;
  evidenceHash: string;
  title: string;
  actor: string;
  victim: string;
  victimDomain: string | null;
  postedAt: string | null;
  volume: number | null;
  dataClasses: DataClass[];
  price: string;
  reference: string;
  indicators: MinIndicator[];
}

export const LIMITS = { events: 100, indicators: 5000, bodyBytes: 2_000_000 };

const PASSWORD_KEYS = ["password", "passwords", "pass", "pwd", "password_hash", "hash", "hashes", "plaintext"];
const COOKIE_KEYS = ["cookie", "cookies", "session", "sessions", "token", "tokens"];
const PII_KEYS = ["phone", "address", "name", "full_name", "dob", "birthdate", "national_id", "passport", "pii"];
const present = (o: Record<string, unknown>, keys: string[]) => keys.some((k) => o[k] !== undefined && o[k] !== null && o[k] !== false && o[k] !== "");

const str = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max) : "");

function isoOrNull(v: unknown): string | null {
  if (typeof v !== "string" && typeof v !== "number") return null;
  const t = new Date(v).getTime();
  if (!Number.isFinite(t)) return null;
  // Dates futures (horloges fantaisistes) ramenées à maintenant
  return new Date(Math.min(t, Date.now())).toISOString();
}

/** Un identifiant reçu → indicateur minimisé, ou null s'il est invalide. La valeur en clair n'en sort jamais. */
export function minimizeIndicator(raw: unknown, pepper: string): MinIndicator | null {
  if (typeof raw === "string") raw = { value: raw };
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const value = str(o.value ?? o.email ?? o.username ?? o.domain ?? o.ip, 320).toLowerCase();
  if (!value) return null;
  let type = str(o.type ?? o.kind, 20).toLowerCase();
  if (!type) type = EMAIL_RE.test(value) ? "email" : IPV4_RE.test(value) ? "ip" : normalizeDomain(value) === value ? "domain" : "username";
  const flags = { hasPassword: present(o, PASSWORD_KEYS), hasCookie: present(o, COOKIE_KEYS), hasPii: present(o, PII_KEYS) };

  if (type === "email" || type === "email-addr") {
    if (!EMAIL_RE.test(value)) return null;
    const domain = value.slice(value.lastIndexOf("@") + 1);
    return { kind: "email", domain, valueHash: keyedHash(pepper, "email", value), masked: maskEmail(value), ...flags };
  }
  if (type === "domain" || type === "hostname" || type === "domain-name" || type === "url") {
    const d = normalizeDomain(value);
    if (!d) return null;
    return { kind: "domain", domain: d, valueHash: keyedHash(pepper, "domain", d), masked: d, ...flags };
  }
  if (type === "ip" || type === "ipv4" || type === "ipv6" || type === "ip-src" || type === "ip-dst") {
    if (!IPV4_RE.test(value) && !(value.includes(":") && IPV6_RE.test(value))) return null;
    return { kind: "ip", domain: null, valueHash: keyedHash(pepper, "ip", value), masked: maskIp(value), ...flags };
  }
  if (type === "username" || type === "login" || type === "user") {
    if (value.length < 2) return null;
    // « login@domaine » sans format e-mail valide : on garde le domaine éventuel pour la corrélation
    const d = typeof o.domain === "string" ? normalizeDomain(o.domain) : null;
    return { kind: "username", domain: d, valueHash: keyedHash(pepper, "username", value), masked: maskUsername(value), ...flags };
  }
  return null;
}

export function evidenceHashOf(sourceId: number, e: { evidence?: string; externalId: string | null; title: string; victim: string; postedAt: string | null }): string {
  if (e.evidence && /^[a-f0-9]{64}$/i.test(e.evidence)) return e.evidence.toLowerCase();
  const basis = e.externalId ? `${sourceId}|id|${e.externalId}` : `${e.title.toLowerCase()}|${e.victim.toLowerCase()}|${(e.postedAt ?? "").slice(0, 10)}`;
  return createHash("sha256").update(basis).digest("hex");
}

/**
 * Valide un lot reçu ({ events: [...] } ou un seul événement) et le minimise.
 * Les champs inconnus sont ignorés ; les secrets ne servent qu'à positionner des indicateurs de présence.
 */
export function parseIncoming(body: unknown, sourceId: number, pepper: string): { events: MinEvent[]; rejected: string[] } {
  const list = body && typeof body === "object" && Array.isArray((body as { events?: unknown }).events) ? (body as { events: unknown[] }).events : [body];
  const rejected: string[] = [];
  const events: MinEvent[] = [];
  if (list.length > LIMITS.events) return { events: [], rejected: [`Au plus ${LIMITS.events} événements par envoi.`] };
  list.forEach((raw, i) => {
    if (!raw || typeof raw !== "object") return void rejected.push(`#${i + 1} : objet attendu`);
    const o = raw as Record<string, unknown>;
    const title = str(o.title, 300);
    if (!title) return void rejected.push(`#${i + 1} : « title » obligatoire`);
    const rawInd = Array.isArray(o.indicators) ? o.indicators : [];
    if (rawInd.length > LIMITS.indicators) return void rejected.push(`#${i + 1} : au plus ${LIMITS.indicators} identifiants`);
    const seen = new Set<string>();
    const indicators: MinIndicator[] = [];
    let invalid = 0;
    for (const r of rawInd) {
      const m = minimizeIndicator(r, pepper);
      if (!m) invalid++;
      else if (!seen.has(m.valueHash)) seen.add(m.valueHash), indicators.push(m);
    }
    if (invalid) rejected.push(`#${i + 1} : ${invalid} identifiant(s) invalide(s) ignoré(s)`);
    const externalId = str(o.external_id ?? o.id, 200) || null;
    const victim = str(o.victim, 200);
    const victimDomain = typeof o.victim_domain === "string" ? normalizeDomain(o.victim_domain) : null;
    const postedAt = isoOrNull(o.posted_at);
    const classes = new Set<DataClass>((Array.isArray(o.data_classes) ? o.data_classes : []).filter((c): c is string => typeof c === "string").map(normalizeClass));
    if (indicators.some((x) => x.hasPassword)) classes.add("passwords");
    if (indicators.some((x) => x.hasCookie)) classes.add("cookies");
    if (indicators.some((x) => x.kind === "email")) classes.add("emails");
    const volume = typeof o.volume === "number" && Number.isFinite(o.volume) && o.volume >= 0 ? Math.min(Math.round(o.volume), 2_000_000_000) : null;
    events.push({
      externalId,
      evidenceHash: evidenceHashOf(sourceId, { evidence: str(o.evidence_sha256, 64), externalId, title, victim, postedAt }),
      title,
      actor: str(o.actor, 120),
      victim,
      victimDomain,
      postedAt,
      volume,
      dataClasses: [...classes].sort(),
      price: str(o.price, 60),
      reference: str(o.reference ?? o.url, 600),
      indicators,
    });
  });
  return { events, rejected };
}

// ---------- Clés d'ingestion ----------

/** Clé d'une source : « vqk_<id>_<sel>_<signature> ». Rien n'est stocké hormis le sel ; la révocation change le sel. */
export function newSalt(): string {
  return randomBytes(9).toString("base64url");
}
const keySig = (secret: string, id: number, salt: string) => createHmac("sha256", secret).update(`leak-source:${id}:${salt}`).digest("base64url").slice(0, 32);
export const ingestKey = (secret: string, id: number, salt: string) => `vqk_${id}_${salt}_${keySig(secret, id, salt)}`;

export function parseIngestKey(key: string): { id: number; salt: string; sig: string } | null {
  const m = /^vqk_(\d{1,9})_([A-Za-z0-9_-]{12})_([A-Za-z0-9_-]{32})$/.exec(key);
  return m ? { id: Number(m[1]), salt: m[2], sig: m[3] } : null;
}

const safeEq = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export function keyMatches(secret: string, key: string, salt: string | null): boolean {
  const p = parseIngestKey(key);
  return Boolean(p && salt && p.salt === salt && safeEq(p.sig, keySig(secret, p.id, salt)));
}

/** Signature du corps : HMAC-SHA256(clé, « horodatage.corps »), en hexadécimal, préfixée « sha256= ». */
export const signBody = (key: string, ts: string, body: string) => `sha256=${createHmac("sha256", key).update(`${ts}.${body}`).digest("hex")}`;

export function verifySignature(key: string, ts: string | null, body: string, sig: string | null, now = Date.now(), skewMs = 5 * 60_000): string | null {
  if (!ts || !sig) return "En-têtes X-VQ-Timestamp et X-VQ-Signature obligatoires.";
  const t = Number(ts) * (ts.length <= 10 ? 1000 : 1);
  if (!Number.isFinite(t) || Math.abs(now - t) > skewMs) return "Horodatage hors de la fenêtre de 5 minutes.";
  return safeEq(sig.trim(), signBody(key, ts, body)) ? null : "Signature invalide.";
}

// ---------- Score de gravité ----------

const REL_W: Record<string, number> = { A: 1, B: 0.9, C: 0.75, D: 0.55, E: 0.4, F: 0.5 };
const STATUS_W: Record<string, number> = { confirmed: 1, sample_verified: 0.8, claimed: 0.5, false_positive: 0 };

export function freshness(date: string | Date | null, now = Date.now()): number {
  if (!date) return 0.7;
  const days = (now - new Date(date).getTime()) / 86_400_000;
  return days <= 7 ? 1 : days <= 30 ? 0.85 : days <= 90 ? 0.65 : days <= 365 ? 0.45 : 0.3;
}

export function sensitivity(classes: string[], flags: { password?: boolean; cookie?: boolean; pii?: boolean } = {}): number {
  const has = (c: string) => classes.includes(c);
  if (flags.cookie || has("cookies")) return 1;
  if (flags.password || has("passwords") || has("financial")) return 0.95;
  if (has("credentials")) return 0.85;
  if (flags.pii || has("pii") || has("documents")) return 0.75;
  if (has("emails")) return 0.45;
  return 0.55;
}

/** Facteur « nombre de comptes touchés » : 1 compte = 0,6 ; 10 = 0,8 ; 100 et plus = 1. */
export const reach = (n: number) => (n <= 0 ? 0.5 : Math.min(1, 0.6 + 0.2 * Math.log10(n)));

/** gravité = fiabilité × fraîcheur × sensibilité × portée × statut, ramenée sur 100. */
export function leakScore(i: { reliability: string; date: string | Date | null; classes: string[]; flags?: { password?: boolean; cookie?: boolean; pii?: boolean }; count: number; status: string; mode?: string }, now = Date.now()): number {
  const modeW = i.mode === "brand" || i.mode === "typosquat" ? 0.6 : 1;
  const s = (REL_W[i.reliability] ?? 0.5) * freshness(i.date, now) * sensitivity(i.classes, i.flags) * reach(i.count) * (STATUS_W[i.status] ?? 0.5) * modeW;
  return Math.round(Math.min(1, s) * 100);
}


// ---------- Domaines ressemblants ----------

function damerau(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) {
      const c = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  return d[a.length][b.length];
}
const deglyph = (s: string) => s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d").replace(/0/g, "o").replace(/1/g, "l").replace(/[-_]/g, "");

/** Le domaine ressemble au domaine surveillé (sans être lui ni un de ses sous-domaines). */
export function isLookalike(candidate: string, watched: string): boolean {
  if (candidate === watched || candidate.endsWith(`.${watched}`)) return false;
  const a = brandOf(candidate);
  const b = brandOf(watched);
  if (b.length < 4) return false;
  if (a === b) return true; // même nom, autre extension
  if (deglyph(a) === deglyph(b)) return true;
  return Math.abs(a.length - b.length) <= 1 && damerau(a, b) === 1;
}

// ---------- Conversion MISP et STIX 2.1 ----------

type Json = Record<string, unknown>;
const arr = (v: unknown): Json[] => (Array.isArray(v) ? (v.filter((x) => x && typeof x === "object") as Json[]) : []);

const MISP_TYPES: Record<string, string> = {
  "email-src": "email", "email-dst": "email", email: "email", "target-email": "email",
  domain: "domain", hostname: "domain", "domain|ip": "domain", url: "url",
  "ip-src": "ip", "ip-dst": "ip", "target-user": "username", "github-username": "username", "text": "",
};

/** Réponse de « /events/restSearch » (MISP) → événements au format d'ingestion. */
export function mispToEvents(json: unknown): Json[] {
  const resp = (json && typeof json === "object" && "response" in (json as Json) ? (json as Json).response : json) as unknown;
  return arr(resp).map((w) => {
    const ev = (w.Event ?? w) as Json;
    const attrs = [...arr(ev.Attribute), ...arr(ev.Object).flatMap((o) => arr(o.Attribute))];
    const tags = arr(ev.Tag).map((t) => String(t.name ?? "")).filter(Boolean);
    const indicators = attrs
      .map((a) => {
        const t = MISP_TYPES[String(a.type ?? "")];
        if (!t) return null;
        const value = String(a.value ?? "").split("|")[0];
        return t === "url" ? { type: "domain", value } : { type: t, value };
      })
      .filter((x): x is { type: string; value: string } => x !== null);
    const orgc = (ev.Orgc ?? {}) as Json;
    return {
      external_id: `misp:${ev.uuid ?? ev.id}`,
      title: String(ev.info ?? "Événement MISP"),
      actor: String(orgc.name ?? ""),
      posted_at: ev.date ?? (ev.publish_timestamp ? Number(ev.publish_timestamp) * 1000 : undefined),
      data_classes: tags.map((t) => t.replace(/^.*[:=]/, "").replace(/"/g, "")),
      indicators,
    };
  });
}

const STIX_VALUE = /\[(email-addr|domain-name|ipv4-addr|ipv6-addr|user-account):(?:value|user_id|account_login)\s*=\s*'([^']+)'\]/g;
const STIX_TYPE: Record<string, string> = { "email-addr": "email", "domain-name": "domain", "ipv4-addr": "ip", "ipv6-addr": "ip", "user-account": "username" };

/** Objets STIX 2.1 (enveloppe TAXII « objects ») → un événement par rapport (« report »). */
export function stixToEvents(objects: unknown): Json[] {
  const list = arr(objects && typeof objects === "object" && "objects" in (objects as Json) ? (objects as Json).objects : objects);
  const byId = new Map(list.map((o) => [String(o.id), o]));
  const indicatorsOf = (o: Json): { type: string; value: string }[] => {
    const t = String(o.type);
    if (STIX_TYPE[t]) return [{ type: STIX_TYPE[t], value: String(o.value ?? o.user_id ?? o.account_login ?? "") }];
    if (t === "indicator") return [...String(o.pattern ?? "").matchAll(STIX_VALUE)].map((m) => ({ type: STIX_TYPE[m[1]], value: m[2] }));
    if (t === "observed-data") return (Array.isArray(o.object_refs) ? o.object_refs : []).flatMap((r) => (byId.get(String(r)) ? indicatorsOf(byId.get(String(r))!) : []));
    return [];
  };
  return list
    .filter((o) => o.type === "report")
    .map((r) => {
      const refs = (Array.isArray(r.object_refs) ? r.object_refs : []).map((x) => byId.get(String(x))).filter((x): x is Json => Boolean(x));
      const actor = refs.find((x) => x.type === "threat-actor" || x.type === "intrusion-set");
      const victim = refs.find((x) => x.type === "identity");
      return {
        external_id: `stix:${r.id}`,
        title: String(r.name ?? "Rapport STIX"),
        actor: String(actor?.name ?? ""),
        victim: String(victim?.name ?? ""),
        posted_at: r.published ?? r.created,
        data_classes: Array.isArray(r.labels) ? r.labels : [],
        reference: Array.isArray(r.external_references) ? String((r.external_references[0] as Json | undefined)?.url ?? "") : "",
        indicators: refs.flatMap(indicatorsOf),
      };
    });
}

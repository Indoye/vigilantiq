/**
 * Comptes exposés d'un domaine dont l'utilisateur a prouvé la propriété (enregistrement DNS TXT).
 *
 * Pour chaque adresse déclarée : fuites de données qui la contiennent (XposedOrNot, sans clé) et infections
 * de postes par des infostealers (Hudson Rock, outil gratuit). On ne garde que des métadonnées utiles à la
 * remédiation : jamais de mot de passe (même masqué), d'identifiant, d'adresse IP ni de chemin de fichier.
 */
import type { AlertDraft, Severity } from "./match.ts";

const UA = "vigilantiq/0.3 (+https://vigilantiq.vercel.app)";
const str = (v: unknown) => (typeof v === "string" ? v.trim() : v == null ? "" : String(v));

export type PasswordRisk = "plaintext" | "easytocrack" | "hardtocrack" | "unknown";

export interface AccountBreach {
  name: string;
  domain: string;
  date: string;
  added: string | null;
  records: number;
  dataTypes: string[];
  passwordRisk: PasswordRisk;
  industry: string;
  details: string;
}

export interface AccountStealer {
  date: string | null;
  computer: string;
  os: string;
  antiviruses: string[];
  corporateServices: number;
  userServices: number;
}

const EMAIL_RE = /^[a-z0-9._%+'-]{1,64}@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function normalizeEmail(input: string): string | null {
  const e = input.trim().toLowerCase().replace(/^mailto:/, "").replace(/^<|>$/g, "");
  return EMAIL_RE.test(e) ? e : null;
}

/** Extrait les adresses d'un texte collé (une par ligne, CSV, séparées par des virgules ou des espaces). */
export function extractEmails(text: string): string[] {
  const found = text.match(/[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}/g) ?? [];
  return [...new Set(found.map((e) => normalizeEmail(e)).filter((e): e is string => Boolean(e)))];
}

export const emailDomain = (email: string) => email.slice(email.lastIndexOf("@") + 1);
export const belongsTo = (email: string, domain: string) => {
  const d = emailDomain(email);
  return d === domain || d.endsWith(`.${domain}`);
};

const RISKS: PasswordRisk[] = ["plaintext", "easytocrack", "hardtocrack", "unknown"];

export function parseBreachAnalytics(json: unknown): AccountBreach[] {
  const j = (json ?? {}) as { ExposedBreaches?: { breaches_details?: unknown } | null };
  const list = Array.isArray(j.ExposedBreaches?.breaches_details) ? (j.ExposedBreaches!.breaches_details as Record<string, unknown>[]) : [];
  return list
    .filter((b) => str(b.breach))
    .map((b) => {
      const risk = str(b.password_risk).toLowerCase() as PasswordRisk;
      return {
        name: str(b.breach),
        domain: str(b.domain).toLowerCase(),
        date: str(b.xposed_date),
        added: str(b.added) || null,
        records: Number(b.xposed_records) || 0,
        dataTypes: str(b.xposed_data)
          .split(";")
          .map((x) => x.trim())
          .filter(Boolean)
          .slice(0, 20),
        passwordRisk: RISKS.includes(risk) ? risk : "unknown",
        industry: str(b.industry),
        details: str(b.details).slice(0, 320),
      };
    })
    .sort((a, b) => b.date.localeCompare(a.date));
}

/** Métadonnées d'infection seulement : on écarte volontairement mots de passe, identifiants, IP et chemins. */
export function parseStealers(json: unknown): AccountStealer[] {
  const list = Array.isArray((json as { stealers?: unknown })?.stealers) ? ((json as { stealers: Record<string, unknown>[] }).stealers) : [];
  return list
    .map((s) => ({
      date: str(s.date_compromised) || null,
      computer: str(s.computer_name).slice(0, 80),
      os: str(s.operating_system).slice(0, 80),
      antiviruses: Array.isArray(s.antiviruses) ? (s.antiviruses as unknown[]).map(str).filter(Boolean).slice(0, 5) : [],
      corporateServices: Number(s.total_corporate_services) || 0,
      userServices: Number(s.total_user_services) || 0,
    }))
    .sort((a, b) => (b.date ?? "").localeCompare(a.date ?? ""));
}

async function getJson(url: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, { headers: { "User-Agent": UA, Accept: "application/json" }, signal: AbortSignal.timeout(15000), cache: "no-store" });
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

export async function fetchAccountBreaches(email: string): Promise<AccountBreach[]> {
  const { status, body } = await getJson(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`);
  if (status === 404) return [];
  if (status === 429) throw new Error("XposedOrNot : trop de requêtes, nouvel essai plus tard");
  if (status >= 400) throw new Error(`XposedOrNot : HTTP ${status}`);
  return parseBreachAnalytics(body);
}

export async function fetchAccountStealers(email: string): Promise<AccountStealer[]> {
  const { status, body } = await getJson(`https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(email)}`);
  if (status === 404) return [];
  if (status >= 400) throw new Error(`Hudson Rock : HTTP ${status}`);
  return parseStealers(body);
}

// ---------- Alertes ----------

const RISK_FR: Record<PasswordRisk, string> = {
  plaintext: "mot de passe en clair",
  easytocrack: "mot de passe facile à casser",
  hardtocrack: "mot de passe chiffré solidement",
  unknown: "protection du mot de passe inconnue",
};

export function draftAccount(email: string, breaches: AccountBreach[], stealers: AccountStealer[]): AlertDraft[] {
  const out: AlertDraft[] = [];
  for (const s of stealers) {
    out.push({
      source: "account",
      externalId: `acct-stealer:${email}:${s.date ?? s.computer}`,
      watchValue: emailDomain(email),
      severity: "critique",
      title: `${email} : poste infecté par un infostealer${s.date ? ` le ${s.date.slice(0, 10)}` : ""}`,
      detail: { email, kind: "stealer", ...s },
      url: "https://www.hudsonrock.com/free-tools",
    });
  }
  for (const b of breaches) {
    const pw = b.dataTypes.some((d) => /password/i.test(d));
    const severity: Severity = pw && (b.passwordRisk === "plaintext" || b.passwordRisk === "easytocrack") ? "haute" : "moyenne";
    out.push({
      source: "account",
      externalId: `acct-breach:${email}:${b.name}`,
      watchValue: emailDomain(email),
      severity,
      title: `${email} figure dans la fuite « ${b.name} »${pw ? ` (${RISK_FR[b.passwordRisk]})` : ""}`,
      detail: { email, kind: "breach", ...b },
      url: `https://xposedornot.com/xposed#${encodeURIComponent(b.name)}`,
    });
  }
  return out;
}

// ---------- Vérification de propriété (DNS TXT) ----------

export const TXT_PREFIX = "vigilantiq-verification=";

export async function domainHasToken(domain: string, token: string): Promise<boolean> {
  const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`, {
    headers: { Accept: "application/dns-json" },
    signal: AbortSignal.timeout(8000),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`DNS HTTP ${res.status}`);
  const j = (await res.json()) as { Answer?: { type: number; data: string }[] };
  const want = `${TXT_PREFIX}${token}`;
  return (j.Answer ?? []).some((a) => a.type === 16 && a.data.replace(/"\s*"/g, "").replace(/^"|"$/g, "").trim() === want);
}

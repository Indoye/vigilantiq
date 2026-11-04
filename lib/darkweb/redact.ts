/**
 * Masquage à l'ingestion des pages collectées sur le dark web.
 *
 * Rien de ce qui permettrait de réutiliser une donnée volée n'est conservé :
 * - e-mails : remplacés par « [e-mail @domaine] » ; seule une empreinte HMAC est gardée pour la correspondance exacte ;
 * - mots de passe, couples identifiant:mot de passe, clés d'API, jetons, clés privées, cookies de session : « [secret masqué] » ;
 * - numéros de téléphone, cartes bancaires, IBAN, adresses IP : masqués et seulement comptés ;
 * - portefeuilles de cryptomonnaies : conservés (indicateurs publics d'infrastructure criminelle).
 * Le module est pur (sans accès réseau ni base) pour être testé isolément.
 */
import { createHmac } from "node:crypto";

export const MAX_TEXT = 60_000;

export interface Redacted {
  text: string;
  emailHashes: string[];
  emailDomains: string[];
  wallets: string[];
  counts: { emails: number; secrets: number; credentials: number; phones: number; cards: number; ips: number; ibans: number };
}

const EMAIL = /\b[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})\b/g;

/** Lignes « identifiant:mot de passe » ou « e-mail;mot de passe » des listes de combos. */
const COMBO = /(^|[\s"'(])([A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}|[A-Za-z0-9._-]{3,40})[:;|][^\s:;|]{4,128}(?=$|[\s"')])/gm;

/** Valeurs qui suivent un libellé de secret : password=…, pass: …, token = "…", api_key … */
const LABELLED = /\b(pass(?:word|wd)?|pwd|mdp|mot de passe|secret|token|api[_-]?key|apikey|access[_-]?key|auth|bearer|session(?:id)?|cookie|private[_-]?key|seed|mnemonic)\b(\s*[:=]\s*|\s+)("[^"\n]{4,200}"|'[^'\n]{4,200}'|[^\s,;"'<>]{4,200})/gi;

/** Formats de secrets reconnaissables sans libellé. */
const SECRET_FORMATS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, // AWS
  /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, // GitHub
  /\bgithub_pat_[A-Za-z0-9_]{60,255}\b/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,200}\b/g, // Slack
  /\bsk_(?:live|test)_[A-Za-z0-9]{16,200}\b/g, // Stripe
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,200}\b/g, // clés d'API d'IA
  /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, // JWT
  /\b[a-f0-9]{32,128}\b/gi, // empreintes et jetons hexadécimaux (hash de mots de passe, jetons de session)
  /\$(?:2[aby]|argon2(?:id|i|d)|[156])\$[^\s]{20,200}/g, // hash bcrypt / crypt
];

const PHONE = /(?<![\w+])(?:\+|00)?\d[\d .()-]{7,18}\d(?!\w)/g;
const CARD = /\b(?:\d[ -]?){13,19}\b/g;
const IBAN = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,8}(?:[ ]?[A-Z0-9]{1,4})?\b/g;
const IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
const IPV6 = /\b(?:[A-Fa-f0-9]{1,4}:){4,7}[A-Fa-f0-9]{1,4}\b/g;

const WALLETS: RegExp[] = [
  /\b(?:bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, // Bitcoin
  /\b0x[a-fA-F0-9]{40}\b/g, // Ethereum et compatibles
  /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g, // Monero
  /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g, // Tron
];

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Empreinte d'une adresse e-mail (normalisée), identique à celle utilisée pour les motifs « e-mail ». */
export function emailHash(email: string, secret: string): string {
  return createHmac("sha256", secret).update(`dw-email:${email.trim().toLowerCase()}`).digest("hex").slice(0, 40);
}

export function redact(input: string, secret: string, extraEmails: string[] = []): Redacted {
  let text = (input ?? "").replace(/\u0000/g, "").slice(0, MAX_TEXT * 2);
  const counts = { emails: 0, secrets: 0, credentials: 0, phones: 0, cards: 0, ips: 0, ibans: 0 };
  const hashes = new Set<string>();
  const domains = new Set<string>();
  const wallets = new Set<string>();

  // 1. Secrets d'abord (une clé privée ou un combo contient souvent un e-mail)
  for (const re of SECRET_FORMATS.slice(0, 1)) text = text.replace(re, () => (counts.secrets++, "[secret masqué]"));
  // Les portefeuilles sont mis de côté avant le masquage des chaînes hexadécimales
  for (const re of WALLETS) for (const m of text.matchAll(re)) wallets.add(m[0]);
  const seen = (email: string) => {
    hashes.add(emailHash(email, secret));
    domains.add(email.split("@")[1].toLowerCase());
  };
  text = text.replace(COMBO, (_m, pre: string, id: string) => {
    counts.credentials++;
    if (id.includes("@")) {
      seen(id);
      return `${pre}[identifiant masqué @${id.split("@")[1].toLowerCase()}]`;
    }
    return `${pre}[identifiant masqué]`;
  });
  text = text.replace(LABELLED, (_m, label: string, sep: string) => (counts.secrets++, `${label}${sep}[secret masqué]`));
  for (const re of SECRET_FORMATS.slice(1)) {
    text = text.replace(re, (m) => {
      if (wallets.has(m) || /^0x/i.test(m)) return m;
      counts.secrets++;
      return "[secret masqué]";
    });
  }

  // 2. E-mails : domaine visible, adresse remplacée par une empreinte
  for (const e of extraEmails) if (typeof e === "string" && e.includes("@")) seen(e);
  text = text.replace(EMAIL, (m: string, dom: string) => {
    counts.emails++;
    seen(m);
    return `[e-mail @${dom.toLowerCase()}]`;
  });

  // 3. Données personnelles et techniques
  text = text.replace(IBAN, () => (counts.ibans++, "[IBAN masqué]"));
  text = text.replace(CARD, (m) => {
    const d = m.replace(/\D/g, "");
    if (d.length >= 13 && d.length <= 19 && luhn(d)) {
      counts.cards++;
      return "[carte masquée]";
    }
    return m;
  });
  text = text.replace(IPV4, () => (counts.ips++, "[IP]"));
  text = text.replace(IPV6, () => (counts.ips++, "[IP]"));
  text = text.replace(PHONE, (m) => {
    const d = m.replace(/\D/g, "");
    if (d.length < 9 || d.length > 15) return m;
    // Les années, dates et montants restent : un numéro a des séparateurs ou un indicatif
    if (!/^(\+|00)/.test(m) && !/[ .()-]/.test(m.trim())) return m;
    counts.phones++;
    return "[téléphone]";
  });

  return {
    text: text.replace(/[ \t]{2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim().slice(0, MAX_TEXT),
    emailHashes: [...hashes].slice(0, 5000),
    emailDomains: [...domains].slice(0, 500),
    wallets: [...wallets].slice(0, 500),
    counts,
  };
}

/** Adresse .onion v3 (ou sous-page) acceptée comme point de départ d'une collecte. */
export const ONION_URL = /^http:\/\/(?:[a-z0-9-]+\.)?[a-z2-7]{56}\.onion(?:\/[^\s]*)?$/;
export const isOnionUrl = (u: string) => ONION_URL.test(u.trim());

export function hostOf(u: string): string {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return "";
  }
}

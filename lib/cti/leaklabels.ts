/** Référentiels des fuites du darkweb, sans dépendance serveur (utilisables dans le navigateur). */
import type { Severity } from "./match.ts";

export const SOURCE_KINDS = ["forum", "marketplace", "telegram", "paste", "stealer", "provider", "misp", "taxii", "manual"] as const;
export type SourceKind = (typeof SOURCE_KINDS)[number];
export const RELIABILITY = ["A", "B", "C", "D", "E", "F"] as const;
export type Reliability = (typeof RELIABILITY)[number];
export const STATUSES = ["claimed", "sample_verified", "confirmed", "false_positive"] as const;
export type LeakStatus = (typeof STATUSES)[number];
export const DATA_CLASSES = ["credentials", "passwords", "cookies", "pii", "financial", "documents", "emails", "other"] as const;
export type DataClass = (typeof DATA_CLASSES)[number];
export type IndicatorKind = "domain" | "email" | "username" | "ip";

export const SOURCE_KIND_FR: Record<SourceKind, string> = {
  forum: "Forum",
  marketplace: "Place de marché",
  telegram: "Canal Telegram",
  paste: "Site de dépôt",
  stealer: "Journaux d’infostealer",
  provider: "Fournisseur",
  misp: "MISP",
  taxii: "TAXII",
  manual: "Saisie analyste",
};
export const RELIABILITY_FR: Record<Reliability, string> = {
  A: "A · totalement fiable",
  B: "B · généralement fiable",
  C: "C · assez fiable",
  D: "D · peu fiable",
  E: "E · non fiable",
  F: "F · fiabilité inconnue",
};
export const STATUS_FR: Record<LeakStatus, string> = {
  claimed: "Revendiquée",
  sample_verified: "Échantillon vérifié",
  confirmed: "Confirmée",
  false_positive: "Fausse",
};
export const CLASS_FR: Record<DataClass, string> = {
  credentials: "Identifiants",
  passwords: "Mots de passe",
  cookies: "Cookies de session",
  pii: "Données personnelles",
  financial: "Données bancaires",
  documents: "Documents",
  emails: "Adresses e-mail",
  other: "Autres",
};


export const severityOf = (score: number): Severity => (score >= 60 ? "critique" : score >= 40 ? "haute" : score >= 20 ? "moyenne" : "info");

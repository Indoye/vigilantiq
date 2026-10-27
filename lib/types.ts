export type Priority = "urgente" | "haute" | "moyenne" | "basse";

export interface KevInfo {
  name: string;
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
  action: string;
}

/** Produit touché, tel que décrit par une source (NVD, CNA = éditeur via CVE.org, OSV). */
export interface AffectedProduct {
  source: "NVD" | "CNA" | "OSV";
  vendor: string;
  product: string;
  ecosystem?: string;
  /** Plages lisibles : "7.0.0 → 7.0.13", "< 2.4.1", "4.2.0" */
  ranges: string[];
  /** Versions qui corrigent la faille, quand la source les donne */
  fixed: string[];
  /** Plateformes ou composants requis (ex. « sur Windows Server 2022 ») */
  platforms: string[];
}

export interface Reference {
  url: string;
  tags: string[];
}

export type FeedKind = "cert" | "gouv" | "editeur" | "exploit" | "cve";

export interface Mention {
  source: string;
  kind: FeedKind;
  title: string;
  link: string;
  published: string;
}

export interface Ssvc {
  exploitation: string | null;
  automatable: string | null;
  technicalImpact: string | null;
}

export interface Vuln {
  id: string;
  published: string;
  description: string;
  cvss: number | null;
  cvssVersion: string | null;
  cvssSource: string | null;
  severity: string | null;
  vector: string | null;
  epss: number | null;
  epssPercentile: number | null;
  kev: KevInfo | null;
  ssvc: Ssvc | null;
  vendors: string[];
  products: string[];
  cwes: string[];
  references: Reference[];
  affected: AffectedProduct[];
  mentions: Mention[];
  /** nvd = publiée dans la fenêtre ; kev = ajoutée récemment au catalogue CISA ; rss = signalée par un flux */
  origin: "nvd" | "kev" | "rss";
  score: number;
  priority: Priority;
  reasons: string[];
  ai?: { resume: string; impact: string; action: string };
  /** Codes d'exploitation / PoC publics connus (les plus pertinents d'abord). */
  exploits?: ExploitRef[];
}

/** Code d'exploitation ou preuve de concept publiée. */
export interface ExploitRef {
  url: string;
  cveId: string;
  /** github | exploitdb */
  source: string;
  title: string;
  description: string;
  stars: number;
  publishedAt: string | null;
  firstSeen: string | null;
}

export type RemediationKind = "correctif" | "contournement" | "detection" | "verification";

export interface RemediationStep {
  kind: RemediationKind;
  text: string;
  /** Origine : Éditeur, CISA, NVD, OSV, VigilantIQ, IA */
  source: string;
  /** Texte d'origine (souvent en anglais), quand l'étape le reprend */
  original?: string;
  /** Traduction française du texte d'origine (IA), quand elle est disponible */
  originalFr?: string;
  url?: string;
}

/** Plan de remédiation d'une CVE : quoi faire, dans quel délai, selon quelles sources. */
export interface Remediation {
  /** Délai recommandé, ex. « 48 heures » ou « avant le 14 novembre (échéance CISA) » */
  deadline: string;
  deadlineDate: string | null;
  /** Une phrase de synthèse */
  summary: string;
  steps: RemediationStep[];
  /** true quand au moins une version corrective ou un correctif éditeur est connu */
  patchAvailable: boolean;
}

export interface RssItem {
  key: string;
  source: string;
  sourceId: string;
  kind: FeedKind;
  title: string;
  link: string;
  published: string;
  summary: string;
  cves: string[];
}

export interface SourceStatus {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface RssSnapshot {
  fetchedAt: string;
  items: RssItem[];
  sources: SourceStatus[];
}

export interface Feed {
  generatedAt: string;
  windowHours: number;
  vulns: Vuln[];
  errors: string[];
  aiEnabled: boolean;
  sources: SourceStatus[];
}

export interface DbLink {
  name: string;
  url: string;
  note?: string;
}

export interface CveDetail extends Vuln {
  lastModified: string | null;
  state: string | null;
  cna: string | null;
  dbLinks: DbLink[];
  errors: string[];
  remediation: Remediation;
  /** Tickets déjà créés dans les outils de l'équipe pour cette CVE */
  tickets?: TicketRef[];
}

export interface TicketRef {
  connector: string;
  externalId: string;
  url: string;
  createdAt: string;
}

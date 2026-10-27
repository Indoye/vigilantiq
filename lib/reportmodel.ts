/**
 * Contenu des rapports PDF, sous forme de blocs (titre, tableau, étapes…), indépendant du rendu.
 * - rapport d'une CVE : exhaustif (gravité, versions, remédiation, PoC, alertes, références, sources) ;
 * - rapport d'une sélection : vue d'ensemble puis une fiche complète par CVE.
 * Le rendu PDF est dans pdfrender.ts. Ce module est testable sans générer de PDF.
 */
import { cvssSentence, decodeCvss } from "./cvss.ts";
import { pct, productName, SSVC_FR, vendorName } from "./format.ts";
import { dbLinks } from "./references.ts";
import { buildRemediation } from "./remediation.ts";
import { PRIORITY_LABEL, PRIORITY_ORDER } from "./score.ts";
import type { CveDetail, DbLink, Priority, Remediation, RemediationKind, TicketRef, Vuln } from "./types.ts";

export type Tone = "normal" | "muted" | "red" | "orange" | "green" | "blue";

export interface Cell {
  text: string;
  /** Détail secondaire affiché en dessous, en plus petit (éditeur, adresse, description…) */
  sub?: string;
  link?: string;
  tone?: Tone;
  bold?: boolean;
}

export type Block =
  | { type: "cover"; kicker: string; title: string; subtitle: string; pill: { text: string; tone: Tone }; score: number | null; meta: [string, string][] }
  | { type: "h1"; text: string }
  | { type: "h2"; text: string; pageBreak?: boolean }
  | { type: "p"; text: string; tone?: Tone; small?: boolean; italic?: boolean; lang?: string }
  | { type: "figures"; items: { label: string; value: string; note?: string; tone?: Tone }[] }
  | { type: "callout"; text: string; tone: Tone }
  | { type: "kv"; rows: { k: string; v: string; link?: string; tone?: Tone }[] }
  | { type: "bullets"; items: { text: string; link?: string; sub?: string }[] }
  | { type: "table"; columns: { title: string; width: number }[]; rows: Cell[][]; empty?: string }
  | { type: "steps"; groups: { title: string; tone: Tone; steps: { text: string; source: string; fr?: string; original?: string; url?: string }[] }[] };

export interface ReportMeta {
  title: string;
  subject: string;
  /** Pied de page, ex. « CVE-2026-41120 » */
  footer: string;
}

export interface ReportContext {
  generatedAt: Date;
  generatedBy: string;
  appUrl: string;
  /** Suivi de l'utilisateur qui génère le rapport */
  status?: string | null;
}

const PRIO_TONE: Record<Priority, Tone> = { urgente: "red", haute: "orange", moyenne: "blue", basse: "muted" };
const STATUS_FR: Record<string, string> = { a_traiter: "À traiter", en_cours: "En cours", traitee: "Traitée", non_concernee: "Non concernée" };
const SOURCE_FR: Record<string, string> = { CNA: "Éditeur (CVE.org)", NVD: "NVD", OSV: "OSV" };
const KIND: Record<RemediationKind, { title: string; tone: Tone }> = {
  correctif: { title: "Corriger", tone: "green" },
  contournement: { title: "En attendant le correctif", tone: "orange" },
  detection: { title: "Détecter", tone: "red" },
  verification: { title: "Vérifier", tone: "blue" },
};
const CONNECTOR_FR: Record<string, string> = { jira: "Jira", servicenow: "ServiceNow", xsoar: "Cortex XSOAR", siem: "SIEM" };
const EXPLOIT_SOURCE: Record<string, string> = { github: "GitHub", exploitdb: "Exploit-DB" };

/** Date longue en français, en UTC : « 27 octobre 2026 ». */
export function dateLong(iso: string | null | undefined): string {
  if (!iso) return "–";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(t).toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
}

function dateTime(d: Date): string {
  return `${d.toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" })} à ${d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" })} UTC`;
}

const exploitedOf = (v: Vuln) => Boolean(v.kev) || v.ssvc?.exploitation === "active";

function exploitationLabel(v: Vuln): { value: string; note: string; tone: Tone } {
  if (v.kev) return { value: "Oui", note: v.kev.ransomware ? "CISA KEV, rançongiciels" : "CISA KEV", tone: "red" };
  if (v.ssvc?.exploitation === "active") return { value: "Oui", note: "SSVC CISA", tone: "red" };
  const n = v.exploits?.length ?? 0;
  if (n > 0) return { value: "PoC public", note: `${n} code${n > 1 ? "s" : ""} publié${n > 1 ? "s" : ""}`, tone: "orange" };
  if (v.ssvc?.exploitation === "poc" || v.mentions.some((m) => m.kind === "exploit")) return { value: "PoC public", note: "signalé", tone: "orange" };
  return { value: "Non signalée", note: "à ce jour", tone: "green" };
}

// ---------- Blocs réutilisés par les deux rapports ----------

function figures(v: Vuln, r: Remediation): Block {
  const ex = exploitationLabel(v);
  return {
    type: "figures",
    items: [
      { label: `CVSS${v.cvssVersion ? ` ${v.cvssVersion}` : ""}`, value: v.cvss != null ? v.cvss.toFixed(1).replace(".", ",") : "–", note: v.severity ? severityFr(v.severity) : "non publié", tone: v.cvss != null && v.cvss >= 9 ? "red" : v.cvss != null && v.cvss >= 7 ? "orange" : "normal" },
      { label: "EPSS (30 jours)", value: pct(v.epss), note: v.epssPercentile != null ? `plus que ${Math.round(v.epssPercentile * 100)} % des CVE` : "non disponible" },
      { label: "Exploitation", value: ex.value, note: ex.note, tone: ex.tone },
      { label: "Correctif", value: r.patchAvailable ? "Disponible" : "Non publié", note: r.deadlineDate ? `à appliquer avant le ${dateLong(r.deadlineDate)}` : r.deadline, tone: r.patchAvailable ? "green" : "orange" },
    ],
  };
}

function severityFr(s: string): string {
  return ({ CRITICAL: "Critique", HIGH: "Élevée", MEDIUM: "Moyenne", LOW: "Faible", NONE: "Aucune" } as Record<string, string>)[s.toUpperCase()] ?? s;
}

function summaryText(v: Vuln, r: Remediation): string {
  const what = v.ai?.resume || firstSentence(v.description);
  const ex = exploitedOf(v)
    ? "Elle est exploitée activement."
    : (v.exploits?.length ?? 0) > 0
      ? "Du code d'exploitation circule publiquement."
      : "Aucune exploitation n'est signalée à ce jour.";
  return `${what} Priorité ${PRIORITY_LABEL[v.priority].toLowerCase()} (score ${v.score}/100). ${ex} ${r.summary} Délai recommandé : ${r.deadline}.`;
}

function firstSentence(s: string): string {
  const m = s.match(/^.{20,400}?[.!?](\s|$)/);
  return (m ? m[0] : s.slice(0, 400)).trim();
}

function severityBlocks(v: Vuln): Block[] {
  const rows: { k: string; v: string; link?: string; tone?: Tone }[] = [
    { k: "Score CVSS", v: v.cvss != null ? `${v.cvss.toFixed(1)} / 10${v.severity ? ` (${severityFr(v.severity)})` : ""}` : "Pas encore publié" },
    { k: "Version et source", v: [v.cvssVersion ? `CVSS ${v.cvssVersion}` : null, v.cvssSource ? (v.cvssSource === "NVD" ? "attribué par la NVD" : `attribué par ${v.cvssSource}`) : null].filter(Boolean).join(", ") || "–" },
  ];
  if (v.vector) rows.push({ k: "Vecteur", v: v.vector });
  const sentence = cvssSentence(v.vector);
  if (sentence) rows.push({ k: "Lecture", v: sentence });
  rows.push({ k: "EPSS", v: v.epss != null ? `${pct(v.epss)} de probabilité d'exploitation dans les 30 jours${v.epssPercentile != null ? ` (centile ${Math.round(v.epssPercentile * 100)})` : ""}` : "Non disponible" });
  if (v.ssvc) {
    rows.push({
      k: "SSVC (CISA)",
      v: [
        v.ssvc.exploitation ? `exploitation ${SSVC_FR[v.ssvc.exploitation] ?? v.ssvc.exploitation}` : null,
        v.ssvc.automatable ? `automatisable ${SSVC_FR[v.ssvc.automatable] ?? v.ssvc.automatable}` : null,
        v.ssvc.technicalImpact ? `impact technique ${SSVC_FR[v.ssvc.technicalImpact] ?? v.ssvc.technicalImpact}` : null,
      ]
        .filter(Boolean)
        .join(", "),
    });
  }
  const out: Block[] = [{ type: "kv", rows }];
  const decoded = decodeCvss(v.vector);
  if (decoded.length) {
    out.push({ type: "h2", text: "Détail du vecteur CVSS" });
    out.push({ type: "table", columns: [{ title: "Métrique", width: 0.45 }, { title: "Valeur", width: 0.55 }], rows: decoded.map(([k, val]) => [{ text: k }, { text: val, bold: /élevé|Réseau|Aucun$|Aucune$|Modifiée/.test(val) }]) });
  }
  if (v.kev) {
    out.push({ type: "h2", text: "Catalogue CISA des failles exploitées (KEV)" });
    out.push({
      type: "kv",
      rows: [
        { k: "Intitulé", v: v.kev.name || "–" },
        { k: "Ajoutée au catalogue", v: dateLong(v.kev.dateAdded) },
        { k: "Échéance de correction", v: dateLong(v.kev.dueDate), tone: "red" },
        { k: "Rançongiciels", v: v.kev.ransomware ? "Utilisée dans des campagnes connues" : "Pas d'usage connu" },
        { k: "Action exigée", v: v.kev.action || "–" },
      ],
    });
  }
  return out;
}

function affectedTable(v: Vuln): Block {
  return {
    type: "table",
    columns: [
      { title: "Produit", width: 0.24 },
      { title: "Versions impactées", width: 0.32 },
      { title: "Corrigé en", width: 0.2 },
      { title: "Source", width: 0.24 },
    ],
    rows: v.affected.map((a) => [
      { text: a.product, sub: [a.vendor, a.ecosystem].filter(Boolean).join("\n") || undefined, bold: true },
      { text: a.ranges.join("\n") || "Toutes les versions", sub: a.platforms.length ? `Avec : ${a.platforms.join(", ")}` : undefined, tone: "red" },
      { text: a.fixed.join("\n") || "–", tone: a.fixed.length ? "green" : "muted" },
      { text: SOURCE_FR[a.source] ?? a.source, tone: "muted" },
    ]),
    empty: "Aucune version précise n'est publiée par l'éditeur, la NVD ou OSV. Consultez l'avis de l'éditeur dans les références.",
  };
}

function remediationBlocks(r: Remediation): Block[] {
  return [
    { type: "callout", text: `${r.summary}\nDélai recommandé : ${r.deadline}.`, tone: r.patchAvailable ? "green" : "orange" },
    {
      type: "steps",
      groups: (Object.keys(KIND) as RemediationKind[])
        .map((k) => ({
          title: KIND[k].title,
          tone: KIND[k].tone,
          steps: r.steps.filter((s) => s.kind === k).map((s) => ({ text: s.text, source: s.source, fr: s.originalFr, original: s.original, url: s.url })),
        }))
        .filter((g) => g.steps.length),
    },
  ];
}

function exploitBlocks(v: Vuln): Block[] {
  const list = v.exploits ?? [];
  const fromRss = v.mentions.filter((m) => m.kind === "exploit" && !list.some((e) => e.url === m.link));
  const rows: Cell[][] = [
    ...list.map((e, i) => [
      { text: String(i + 1), tone: "muted" as Tone },
      { text: e.title, sub: `${e.description ? `${e.description}\n` : ""}${e.url}`, link: e.url },
      { text: EXPLOIT_SOURCE[e.source] ?? e.source },
      { text: e.stars ? String(e.stars) : "–" },
      { text: e.publishedAt ? `Publié le ${dateLong(e.publishedAt)}` : "–", sub: e.firstSeen ? `Détecté le ${dateLong(e.firstSeen)}` : undefined, tone: "muted" as Tone },
    ]),
    ...fromRss.map((m, i) => [
      { text: String(list.length + i + 1), tone: "muted" as Tone },
      { text: m.title, sub: m.link, link: m.link },
      { text: m.source },
      { text: "–" },
      { text: m.published ? `Publié le ${dateLong(m.published)}` : "–", tone: "muted" as Tone },
    ]),
  ];
  const out: Block[] = [];
  if (rows.length) {
    out.push({ type: "callout", text: "Code non vérifié, publié par des tiers : certains dépôts sont faux ou piégés. À n'exécuter que dans un environnement isolé, jamais en production.", tone: "orange" });
  }
  out.push({
    type: "table",
    columns: [
      { title: "#", width: 0.05 },
      { title: "Dépôt ou publication", width: 0.47 },
      { title: "Source", width: 0.12 },
      { title: "Étoiles", width: 0.11 },
      { title: "Dates", width: 0.25 },
    ],
    rows,
    empty: v.ssvc?.exploitation === "poc" ? "La CISA signale une preuve de concept publique (SSVC), sans dépôt identifié par VigilantIQ." : "Aucun code d'exploitation public repéré sur GitHub ni sur Exploit-DB à la date du rapport.",
  });
  return out;
}

function mentionsTable(v: Vuln): Block {
  return {
    type: "table",
    columns: [
      { title: "Source", width: 0.18 },
      { title: "Publication", width: 0.62 },
      { title: "Date", width: 0.2 },
    ],
    rows: v.mentions.map((m) => [{ text: m.source, bold: true }, { text: m.title, sub: m.link, link: m.link }, { text: dateLong(m.published), tone: "muted" }]),
    empty: "Aucune alerte d'un CERT, d'une agence ou d'un éditeur suivi ne cite cette CVE à ce jour.",
  };
}

function referencesTable(v: Vuln): Block {
  return {
    type: "table",
    columns: [
      { title: "#", width: 0.06 },
      { title: "Adresse", width: 0.66 },
      { title: "Nature", width: 0.28 },
    ],
    rows: v.references.map((r, i) => [{ text: String(i + 1), tone: "muted" }, { text: r.url, link: r.url }, { text: r.tags.join(", ") || "–", tone: r.tags.includes("Correctif") ? "green" : r.tags.includes("Exploit") ? "red" : "muted" }]),
    empty: "Aucune référence publiée.",
  };
}

function cweBlock(v: Vuln): Block {
  return {
    type: "bullets",
    items: v.cwes.length
      ? v.cwes.map((c) => {
          const n = c.match(/^CWE-(\d+)$/)?.[1];
          return { text: c, link: n ? `https://cwe.mitre.org/data/definitions/${n}.html` : undefined };
        })
      : [{ text: "Type de faiblesse non renseigné par les sources." }],
  };
}

function dbBlock(links: DbLink[]): Block {
  return {
    type: "table",
    columns: [{ title: "Base", width: 0.32 }, { title: "Adresse", width: 0.68 }],
    rows: links.map((d) => [{ text: d.name, sub: d.note, bold: true }, { text: d.url, link: d.url }]),
  };
}

function trackingBlocks(status: string | null | undefined, tickets: TicketRef[] | undefined): Block[] {
  // Le suivi est personnel : absent d'un rapport généré par l'API (jeton d'un outil).
  const out: Block[] = status == null ? [] : [{ type: "kv", rows: [{ k: "Votre suivi", v: STATUS_FR[status] ?? "À traiter" }] }];
  out.push({
    type: "table",
    columns: [
      { title: "Outil", width: 0.2 },
      { title: "Référence", width: 0.5 },
      { title: "Créé le", width: 0.3 },
    ],
    rows: (tickets ?? []).map((t) => [
      { text: CONNECTOR_FR[t.connector] ?? t.connector, bold: true },
      { text: t.externalId, sub: t.url || undefined, link: t.url || undefined },
      { text: dateLong(t.createdAt), tone: "muted" },
    ]),
    empty: "Aucun ticket ni événement envoyé aux outils de l'équipe.",
  });
  return out;
}

const METHOD =
  "Score de priorité de 0 à 100, déterministe : gravité CVSS (jusqu'à 60 points), probabilité d'exploitation EPSS (jusqu'à 25), exploitation active selon la CISA (+30, rançongiciel +5), code d'exploitation public (+10), alerte d'un CERT ou d'une agence (+5). " +
  "Les délais suivent l'échéance CISA quand elle existe, sinon la priorité (48 heures, 7 jours, 30 jours, 90 jours). " +
  "Les résumés et traductions marqués IA sont rédigés par un modèle de langage à partir des fiches officielles : vérifiez l'avis de l'éditeur avant d'agir.";

/** Les blocs d'une fiche complète, partagés par les deux rapports. */
function cveSections(v: Vuln, r: Remediation, opts: { dbLinks: DbLink[]; status?: string | null; tickets?: TicketRef[]; cna?: string | null; lastModified?: string | null; state?: string | null; errors?: string[] }): Block[] {
  const blocks: Block[] = [];
  blocks.push(figures(v, r));
  blocks.push({ type: "h1", text: "Synthèse" });
  blocks.push({ type: "p", text: summaryText(v, r) });

  blocks.push({ type: "h1", text: "Description" });
  if (v.ai) {
    blocks.push({ type: "kv", rows: [{ k: "Résumé (IA)", v: v.ai.resume }, { k: "Impact (IA)", v: v.ai.impact }, { k: "À faire (IA)", v: v.ai.action }] });
    blocks.push({ type: "h2", text: "Description officielle (anglais)" });
  }
  blocks.push({ type: "p", text: v.description || "Pas encore de description publiée.", lang: "en", tone: v.ai ? "muted" : "normal" });

  blocks.push({ type: "h1", text: "Pourquoi cette priorité" });
  blocks.push({ type: "bullets", items: v.reasons.length ? v.reasons.map((x) => ({ text: x })) : [{ text: "Aucun facteur aggravant connu." }] });

  blocks.push({ type: "h1", text: "Gravité et exploitation" });
  blocks.push(...severityBlocks(v));

  blocks.push({ type: "h1", text: "Produits et versions concernés" });
  blocks.push(affectedTable(v));

  blocks.push({ type: "h1", text: "Plan de remédiation" });
  blocks.push(...remediationBlocks(r));

  blocks.push({ type: "h1", text: "Codes d'exploitation et PoC publics" });
  blocks.push(...exploitBlocks(v));

  blocks.push({ type: "h1", text: "Alertes des CERT, agences et éditeurs" });
  blocks.push(mentionsTable(v));

  blocks.push({ type: "h1", text: "Faiblesses (CWE)" });
  blocks.push(cweBlock(v));

  blocks.push({ type: "h1", text: `Références (${v.references.length})` });
  blocks.push(referencesTable(v));

  blocks.push({ type: "h1", text: "Bases de vulnérabilités" });
  blocks.push(dbBlock(opts.dbLinks));

  if (opts.status != null || opts.tickets) {
    blocks.push({ type: "h1", text: "Suivi dans VigilantIQ" });
    blocks.push(...trackingBlocks(opts.status, opts.tickets));
  }

  blocks.push({ type: "h1", text: "Sources et méthode" });
  const sources = [
    "NVD (NIST) : description, score CVSS, configurations CPE",
    `CVE.org : fiche officielle de l'éditeur${opts.cna ? ` (CNA : ${opts.cna})` : ""}, solutions et contournements`,
    "OSV : versions des paquets open source",
    "FIRST EPSS : probabilité d'exploitation",
    "CISA : catalogue KEV et évaluation SSVC",
    "Flux des CERT, agences et éditeurs (CERT-FR, CERT-EU, CISA, CERT/CC, ZDI, Microsoft, Cisco, Fortinet, Palo Alto, Ubuntu, Exploit-DB)",
    "GitHub et PoC-in-GitHub : codes d'exploitation publics",
  ];
  blocks.push({ type: "bullets", items: sources.map((text) => ({ text })) });
  const kv: { k: string; v: string; tone?: Tone }[] = [
    { k: "Publication de la CVE", v: dateLong(v.published) },
    { k: "Dernière modification", v: dateLong(opts.lastModified ?? null) },
  ];
  if (opts.state) kv.push({ k: "État", v: opts.state === "PUBLISHED" ? "Publiée" : opts.state === "REJECTED" ? "Rejetée" : opts.state });
  if (opts.errors?.length) kv.push({ k: "Sources indisponibles", v: opts.errors.join(" ; "), tone: "orange" });
  blocks.push({ type: "kv", rows: kv });
  blocks.push({ type: "p", text: METHOD, small: true, tone: "muted" });
  return blocks;
}

// ---------- Rapport d'une CVE ----------

export function cveReport(d: CveDetail, ctx: ReportContext): { meta: ReportMeta; blocks: Block[] } {
  const vendor = vendorName(d);
  const blocks: Block[] = [
    {
      type: "cover",
      kicker: "VigilantIQ · Rapport de vulnérabilité",
      title: d.id,
      subtitle: `${productName(d)}${vendor ? ` · ${vendor}` : ""}`,
      pill: { text: `Priorité ${PRIORITY_LABEL[d.priority].toLowerCase()}`, tone: PRIO_TONE[d.priority] },
      score: d.score,
      meta: [
        ["Généré le", dateTime(ctx.generatedAt)],
        ["Par", ctx.generatedBy],
        ["Fiche en ligne", `${ctx.appUrl.replace(/\/+$/, "")}/cve/${d.id}`],
        ["Diffusion", "Interne à l'organisation"],
      ],
    },
    ...cveSections(d, d.remediation, { dbLinks: d.dbLinks, status: ctx.status, tickets: d.tickets ?? [], cna: d.cna, lastModified: d.lastModified, state: d.state, errors: d.errors }),
  ];
  return { meta: { title: `${d.id} – rapport VigilantIQ`, subject: `Rapport de vulnérabilité ${d.id}`, footer: d.id }, blocks };
}

// ---------- Rapport d'une sélection ----------

export function selectionReport(vulns: Vuln[], ctx: ReportContext & { title: string; scope: string }): { meta: ReportMeta; blocks: Block[] } {
  const rems = new Map(vulns.map((v) => [v.id, buildRemediation(v, {}, ctx.generatedAt.getTime())]));
  const count = (p: Priority) => vulns.filter((v) => v.priority === p).length;
  const exploited = vulns.filter(exploitedOf).length;
  const withPoc = vulns.filter((v) => (v.exploits?.length ?? 0) > 0).length;
  const patched = vulns.filter((v) => rems.get(v.id)!.patchAvailable).length;

  const blocks: Block[] = [
    {
      type: "cover",
      kicker: "VigilantIQ · Rapport de veille",
      title: ctx.title,
      subtitle: `${vulns.length} vulnérabilité${vulns.length > 1 ? "s" : ""} · ${ctx.scope}`,
      pill: { text: count("urgente") ? `${count("urgente")} urgente${count("urgente") > 1 ? "s" : ""}` : "Aucune urgente", tone: count("urgente") ? "red" : "green" },
      score: null,
      meta: [
        ["Généré le", dateTime(ctx.generatedAt)],
        ["Par", ctx.generatedBy],
        ["Application", ctx.appUrl],
        ["Diffusion", "Interne à l'organisation"],
      ],
    },
    {
      type: "figures",
      items: [
        { label: "Urgentes / hautes", value: `${count("urgente")} / ${count("haute")}`, note: `${count("moyenne")} moyennes, ${count("basse")} basses`, tone: count("urgente") ? "red" : "normal" },
        { label: "Exploitées", value: String(exploited), note: "CISA KEV ou SSVC", tone: exploited ? "red" : "green" },
        { label: "PoC publics", value: String(withPoc), note: "GitHub, Exploit-DB", tone: withPoc ? "orange" : "green" },
        { label: "Correctif disponible", value: `${patched} / ${vulns.length}`, note: "versions corrigées connues", tone: "green" },
      ],
    },
    { type: "h1", text: "Vue d'ensemble" },
    {
      type: "table",
      columns: [
        { title: "CVE", width: 0.19 },
        { title: "Produit", width: 0.23 },
        { title: "Priorité", width: 0.15 },
        { title: "CVSS", width: 0.09 },
        { title: "Menace", width: 0.12 },
        { title: "À traiter avant", width: 0.22 },
      ],
      rows: [...vulns]
        .sort((a, b) => PRIORITY_ORDER.indexOf(a.priority) - PRIORITY_ORDER.indexOf(b.priority) || b.score - a.score)
        .map((v) => {
          const r = rems.get(v.id)!;
          const ex = exploitedOf(v) ? "Exploitée" : (v.exploits?.length ?? 0) > 0 ? `PoC ×${v.exploits!.length}` : "–";
          return [
            { text: v.id, bold: true, link: `${ctx.appUrl.replace(/\/+$/, "")}/cve/${v.id}` },
            { text: productName(v) },
            { text: `${PRIORITY_LABEL[v.priority]} (${v.score})`, tone: PRIO_TONE[v.priority] },
            { text: v.cvss != null ? v.cvss.toFixed(1) : "–" },
            { text: ex, tone: ex === "–" ? "muted" : exploitedOf(v) ? "red" : "orange" },
            { text: r.deadlineDate ? dateLong(r.deadlineDate) : r.deadline },
          ];
        }),
      empty: "Aucune vulnérabilité dans cette sélection.",
    },
  ];

  for (const v of vulns) {
    const vendor = vendorName(v);
    blocks.push({ type: "h2", text: `${v.id} · ${productName(v)}${vendor ? ` (${vendor})` : ""} · priorité ${PRIORITY_LABEL[v.priority].toLowerCase()}, score ${v.score}`, pageBreak: true });
    blocks.push(...cveSections(v, rems.get(v.id)!, { dbLinks: dbLinks(v.id, { kev: Boolean(v.kev), osv: v.affected.some((a) => a.source === "OSV") }) }));
  }
  return { meta: { title: `${ctx.title} – rapport VigilantIQ`, subject: ctx.title, footer: ctx.title }, blocks };
}

/** Texte compatible avec la police du rapport : plages de versions en toutes lettres, symboles remplacés. */
export function pdfText(s: string): string {
  return s
    .replace(/> (\S+) → < (\S+)/g, "après $1 et avant $2")
    .replace(/(\S+) → < (\S+)/g, "de $1 à $2 (exclue)")
    .replace(/(\S+) → (\S+)/g, "de $1 à $2")
    .replace(/≤ /g, "jusqu'à ")
    .replace(/≥ /g, "à partir de ")
    .replace(/→/g, "à")
    .replace(/[★✓✔]/g, "")
    .replace(/[  ]/g, " ");
}

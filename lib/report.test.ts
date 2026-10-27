import { test } from "node:test";
import assert from "node:assert/strict";
import { cvssSentence, decodeCvss } from "./cvss.ts";
import { buildRemediation } from "./remediation.ts";
import { cveReport, pdfText, selectionReport, type Block } from "./reportmodel.ts";
import type { CveDetail, Vuln } from "./types.ts";

const NOW = new Date("2026-10-27T12:00:00Z");

function vuln(over: Partial<Vuln> = {}): Vuln {
  return {
    id: "CVE-2026-41120",
    published: "2026-10-26T10:00:00Z",
    description: "Heap overflow in FortiOS SSL-VPN allows remote code execution. More details follow here.",
    cvss: 9.8,
    cvssVersion: "3.1",
    cvssSource: "NVD",
    severity: "CRITICAL",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    epss: 0.62,
    epssPercentile: 0.99,
    kev: { name: "Fortinet FortiOS Heap Overflow", dateAdded: "2026-10-26", dueDate: "2026-11-16", ransomware: true, action: "Apply mitigations per vendor instructions." },
    ssvc: { exploitation: "active", automatable: "yes", technicalImpact: "total" },
    vendors: ["fortinet"],
    products: ["fortios"],
    cwes: ["CWE-122"],
    references: [{ url: "https://fortiguard.com/psirt/FG-IR-26-001", tags: ["Avis éditeur", "Correctif"] }],
    affected: [{ source: "CNA", vendor: "Fortinet", product: "FortiOS", ranges: ["7.0.0 → < 7.0.14", "≤ 7.2.5"], fixed: ["7.0.14", "7.2.6"], platforms: [] }],
    mentions: [{ source: "CERT-FR", kind: "cert", title: "Multiples vulnérabilités dans FortiOS", link: "https://cert.ssi.gouv.fr/alerte/1", published: "2026-10-27T08:00:00Z" }],
    exploits: [{ url: "https://github.com/a/poc", cveId: "CVE-2026-41120", source: "github", title: "a/poc", description: "RCE PoC", stars: 312, publishedAt: "2026-10-26T00:00:00Z", firstSeen: "2026-10-27T06:30:00Z" }],
    origin: "nvd",
    score: 100,
    priority: "urgente",
    reasons: ["Gravité critique (CVSS 9.8)", "Exploitée activement (catalogue CISA KEV)"],
    ai: { resume: "Débordement dans le VPN SSL de FortiOS.", impact: "Exécution de code à distance.", action: "Mettre à jour." },
    ...over,
  };
}

function detail(): CveDetail {
  const v = vuln();
  return {
    ...v,
    lastModified: "2026-10-27T09:00:00Z",
    state: "PUBLISHED",
    cna: "fortinet",
    dbLinks: [{ name: "NVD", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-41120" }],
    errors: ["EPSS indisponible (délai dépassé)"],
    remediation: buildRemediation(v, { workarounds: ["Disable SSL-VPN web mode."] }, NOW.getTime()),
    tickets: [{ connector: "jira", externalId: "SEC-12", url: "https://x.atlassian.net/browse/SEC-12", createdAt: "2026-10-27T07:00:00Z" }],
  };
}

const ctx = { generatedAt: NOW, generatedBy: "awa@entreprise.sn", appUrl: "https://vigilantiq.vercel.app", status: "en_cours" };
const titles = (blocks: Block[]) => blocks.filter((b) => b.type === "h1").map((b) => (b as { text: string }).text);
const allText = (blocks: Block[]) => JSON.stringify(blocks);

test("rapport CVE : toutes les sections, dans l'ordre", () => {
  const { meta, blocks } = cveReport(detail(), ctx);
  assert.equal(meta.footer, "CVE-2026-41120");
  assert.equal(blocks[0].type, "cover");
  assert.deepEqual(titles(blocks), [
    "Synthèse",
    "Description",
    "Pourquoi cette priorité",
    "Gravité et exploitation",
    "Produits et versions concernés",
    "Plan de remédiation",
    "Codes d'exploitation et PoC publics",
    "Alertes des CERT, agences et éditeurs",
    "Faiblesses (CWE)",
    "Références (1)",
    "Bases de vulnérabilités",
    "Suivi dans VigilantIQ",
    "Sources et méthode",
  ]);
});

test("rapport CVE : contenu exhaustif (KEV, vecteur, PoC, contournement, tickets, suivi, sources indisponibles)", () => {
  const text = allText(cveReport(detail(), ctx).blocks);
  for (const expected of [
    "Fortinet FortiOS Heap Overflow",
    "16 novembre 2026",
    "Apply mitigations per vendor instructions.",
    "Vecteur d'attaque",
    "Réseau (à distance)",
    "https://github.com/a/poc",
    "Disable SSL-VPN web mode.",
    "SEC-12",
    "En cours",
    "EPSS indisponible",
    "https://cert.ssi.gouv.fr/alerte/1",
    "https://cwe.mitre.org/data/definitions/122.html",
    "awa@entreprise.sn",
    "https://vigilantiq.vercel.app/cve/CVE-2026-41120",
  ]) {
    assert.ok(text.includes(expected), `absent du rapport : ${expected}`);
  }
});

test("rapport CVE sans PoC ni alerte : messages explicites plutôt que des sections vides", () => {
  const d = { ...detail(), exploits: [], mentions: [], ssvc: null };
  const text = allText(cveReport(d, ctx).blocks);
  assert.ok(text.includes("Aucun code d'exploitation public repéré"));
  assert.ok(text.includes("Aucune alerte d'un CERT"));
});

test("rapport de sélection : vue d'ensemble triée puis une fiche par CVE, chacune sur une nouvelle page", () => {
  const a = vuln({ id: "CVE-1", priority: "haute", score: 60, kev: null, ssvc: null });
  const b = vuln({ id: "CVE-2" });
  const { blocks } = selectionReport([a, b], { ...ctx, title: "Aujourd'hui", scope: "sélection" });
  const overview = blocks.find((x) => x.type === "table")!;
  assert.equal(overview.type === "table" && overview.rows[0][0].text, "CVE-2", "l'urgente d'abord");
  const pages = blocks.filter((x) => x.type === "h2" && x.pageBreak);
  assert.equal(pages.length, 2);
  assert.equal(titles(blocks).filter((t) => t === "Plan de remédiation").length, 2);
});

test("décodage du vecteur CVSS v3.1 et v4.0", () => {
  assert.deepEqual(decodeCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").slice(0, 3), [
    ["Vecteur d'attaque", "Réseau (à distance)"],
    ["Complexité de l'attaque", "Faible"],
    ["Privilèges requis", "Aucun"],
  ]);
  assert.equal(decodeCvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").length, 11);
  assert.equal(cvssSentence("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "Exploitable à distance par le réseau, sans privilège ni interaction de l'utilisateur.");
  assert.equal(cvssSentence("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"), "Exploitable avec un accès local, avec un compte à faibles privilèges, avec une action de l'utilisateur.");
});

test("plages de versions écrites en toutes lettres pour la police du PDF", () => {
  assert.equal(pdfText("7.0.0 → < 7.0.14"), "de 7.0.0 à 7.0.14 (exclue)");
  assert.equal(pdfText("7.2.0 → 7.2.5"), "de 7.2.0 à 7.2.5");
  assert.equal(pdfText("> 1.0 → < 2.0"), "après 1.0 et avant 2.0");
  assert.equal(pdfText("≤ 7.2.5"), "jusqu'à 7.2.5");
  assert.equal(pdfText("≥ 3.1"), "à partir de 3.1");
});

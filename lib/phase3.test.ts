import { test } from "node:test";
import assert from "node:assert/strict";
import { filterVulns, parseVulnQuery } from "./apifilter.ts";
import { jiraDoc, siemEvent, ticketContent, ticketText } from "./connectors.ts";
import { parseCveOrg } from "./cveorg.ts";
import { cvesIn, exploitsFromRss, parseGithubSearch, parsePocIndex, rankExploits } from "./poc.ts";
import { buildRemediation, remediationDeadline } from "./remediation.ts";
import { scoreVuln } from "./score.ts";
import type { ExploitRef, Vuln } from "./types.ts";

const NOW = Date.parse("2026-10-27T12:00:00Z");

function vuln(over: Partial<Vuln> = {}): Vuln {
  return {
    id: "CVE-2026-41120",
    published: "2026-10-26T10:00:00Z",
    description: "Heap overflow in FortiOS SSL-VPN allows remote code execution.",
    cvss: 9.8,
    cvssVersion: "3.1",
    cvssSource: "NVD",
    severity: "CRITICAL",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    epss: 0.4,
    epssPercentile: 0.98,
    kev: null,
    ssvc: null,
    vendors: ["fortinet"],
    products: ["fortios"],
    cwes: ["CWE-787"],
    references: [
      { url: "https://fortiguard.com/psirt/FG-IR-26-001", tags: ["Avis éditeur"] },
      { url: "https://github.com/x/y/commit/1", tags: ["Correctif"] },
    ],
    affected: [
      { source: "CNA", vendor: "Fortinet", product: "FortiOS", ranges: ["7.0.0 → < 7.0.14", "7.2.0 → < 7.2.7"], fixed: ["7.0.14", "7.2.7"], platforms: [] },
    ],
    mentions: [],
    origin: "nvd",
    score: 90,
    priority: "urgente",
    reasons: [],
    ...over,
  };
}

const poc = (url: string, stars = 0, source = "github"): ExploitRef => ({
  url,
  cveId: "CVE-2026-41120",
  source,
  title: url.split("/").slice(-2).join("/"),
  description: "",
  stars,
  publishedAt: "2026-10-26T00:00:00Z",
  firstSeen: null,
});

// ---------- PoC ----------

test("cvesIn reconnaît les identifiants écrits avec tirets ou soulignés", () => {
  assert.deepEqual(cvesIn("poc for cve_2026_1234 and CVE-2025-99999, again CVE-2026-1234"), ["CVE-2026-1234", "CVE-2025-99999"]);
});

test("parsePocIndex ignore les forks et garde les étoiles", () => {
  const list = parsePocIndex(
    [
      { html_url: "https://github.com/a/poc", full_name: "a/poc", stargazers_count: 12, created_at: "2026-10-01T00:00:00Z", fork: false },
      { html_url: "https://github.com/b/poc", full_name: "b/poc", fork: true },
      { html_url: "javascript:alert(1)", full_name: "c/poc" },
    ],
    "CVE-2026-1",
  );
  assert.equal(list.length, 1);
  assert.equal(list[0].stars, 12);
  assert.equal(list[0].cveId, "CVE-2026-1");
});

test("parseGithubSearch crée une entrée par CVE citée", () => {
  const list = parseGithubSearch({
    items: [
      { html_url: "https://github.com/u/CVE-2026-1111-exploit", name: "CVE-2026-1111-exploit", description: "also CVE-2026-2222", topics: [] },
      { html_url: "https://github.com/u/tool", name: "tool", description: "no cve here" },
    ],
  });
  assert.deepEqual(list.map((e) => e.cveId).sort(), ["CVE-2026-1111", "CVE-2026-2222"]);
});

test("rankExploits : Exploit-DB d'abord, puis les plus étoilés, sans doublon", () => {
  const r = rankExploits([poc("https://github.com/a/1", 3), poc("https://github.com/a/2", 50), poc("https://www.exploit-db.com/exploits/1", 0, "exploitdb"), poc("https://github.com/a/2", 50)]);
  assert.deepEqual(r.map((e) => e.url), ["https://www.exploit-db.com/exploits/1", "https://github.com/a/2", "https://github.com/a/1"]);
});

test("exploitsFromRss ne garde que les éléments de type exploit", () => {
  const list = exploitsFromRss([
    { key: "1", source: "Exploit-DB", sourceId: "exploitdb", kind: "exploit", title: "FortiOS RCE", link: "https://www.exploit-db.com/exploits/9", published: "", summary: "", cves: ["CVE-2026-41120"] },
    { key: "2", source: "CERT-FR", sourceId: "certfr", kind: "cert", title: "Avis", link: "https://cert.fr/1", published: "", summary: "", cves: ["CVE-2026-41120"] },
  ]);
  assert.equal(list.length, 1);
  assert.equal(list[0].source, "exploitdb");
});

test("un PoC public ajoute 10 points et une raison explicite", () => {
  const base = { cvss: 7.5, epss: 0.01, kev: null };
  const without = scoreVuln(base);
  const withPoc = scoreVuln({ ...base, exploitCount: 3 });
  assert.equal(withPoc.score - without.score, 10);
  assert.ok(withPoc.reasons.some((r) => r.includes("3 PoC")));
});

// ---------- Remédiation ----------

test("correctif connu : versions corrigées, délai 48 h pour une urgente", () => {
  const r = buildRemediation(vuln(), {}, NOW);
  assert.equal(r.patchAvailable, true);
  assert.equal(r.deadline, "sous 48 heures");
  assert.equal(r.deadlineDate, "2026-10-29");
  const fix = r.steps.find((s) => s.kind === "correctif")!;
  assert.match(fix.text, /FortiOS \(Fortinet\).*7\.0\.14, 7\.2\.7/);
  assert.match(r.summary, /^Mettre à jour FortiOS/);
  assert.ok(!r.summary.includes("48 heures"), "le délai est affiché à part");
  assert.ok(r.steps.some((s) => s.kind === "verification"));
});

test("faille KEV : échéance CISA, action CISA et recherche de compromission", () => {
  const v = vuln({ kev: { name: "x", dateAdded: "2026-10-20", dueDate: "2026-11-10", ransomware: true, action: "Apply mitigations per vendor instructions." } });
  const r = buildRemediation(v, {}, NOW);
  assert.match(r.deadline, /avant le 10 novembre 2026 \(échéance CISA\)/);
  assert.ok(r.steps.some((s) => s.source === "CISA" && s.original?.startsWith("Apply")));
  assert.ok(r.steps.some((s) => s.kind === "detection" && /compromission/.test(s.text)));
  assert.ok(r.steps.some((s) => /rançongiciels/.test(s.text)));
});

test("échéance CISA dépassée : immédiatement", () => {
  const d = remediationDeadline({ priority: "haute", kev: { name: "", dateAdded: "", dueDate: "2026-10-01", ransomware: false, action: "" } }, NOW);
  assert.match(d.label, /^immédiatement/);
});

test("pas de correctif : contournement de l'éditeur, sinon mesures d'attente selon l'exposition et la CWE", () => {
  const noFix = vuln({ affected: [], references: [], priority: "haute", cwes: ["CWE-22"] });
  const withVendor = buildRemediation(noFix, { workarounds: ["Disable the SSL-VPN web mode."] }, NOW);
  assert.equal(withVendor.patchAvailable, false);
  assert.ok(withVendor.steps.some((s) => s.kind === "contournement" && s.original === "Disable the SSL-VPN web mode."));
  assert.match(withVendor.summary, /contournement de l'éditeur/);

  const generic = buildRemediation(noFix, {}, NOW);
  assert.ok(generic.steps.some((s) => /retirez le service d'Internet/.test(s.text)));
  assert.ok(generic.steps.some((s) => /\.\.\//.test(s.text)), "conseil spécifique au CWE-22");
  assert.match(generic.summary, /Pas encore de correctif publié/);
});

test("solution de l'éditeur reprise telle quelle comme correctif", () => {
  const r = buildRemediation(vuln({ affected: [], references: [] }), { solutions: ["Upgrade to 3.2.1 or later."] }, NOW);
  assert.equal(r.patchAvailable, true);
  assert.equal(r.steps[0].original, "Upgrade to 3.2.1 or later.");
});

test("PoC publics : étape de détection SIEM", () => {
  const r = buildRemediation(vuln({ exploits: [poc("https://github.com/a/1")] }), {}, NOW);
  assert.ok(r.steps.some((s) => s.kind === "detection" && /SIEM/.test(s.text)));
});

test("parseCveOrg extrait solutions, contournements et notes d'exploitation (anglais en priorité)", () => {
  const d = parseCveOrg({
    cveMetadata: { cveId: "CVE-2026-5", state: "PUBLISHED" },
    containers: {
      cna: {
        descriptions: [{ lang: "en", value: "desc" }],
        solutions: [{ lang: "en", value: "Upgrade  to\n 2.0" }, { lang: "fr", value: "Mettre à jour" }],
        workarounds: [{ lang: "en-US", value: "Disable feature X." }],
        exploits: [{ lang: "en", value: "Exploited in the wild." }],
      },
    },
  });
  assert.deepEqual(d.solutions, ["Upgrade to 2.0"]);
  assert.deepEqual(d.workarounds, ["Disable feature X."]);
  assert.deepEqual(d.exploitNotes, ["Exploited in the wild."]);
});

// ---------- Connecteurs ----------

test("contenu du ticket : titre, faits, étapes et lien vers la fiche", () => {
  const v = vuln({ exploits: [poc("https://github.com/a/1", 5)] });
  const c = ticketContent(v, buildRemediation(v, {}, NOW), "https://vigilantiq.vercel.app/");
  assert.equal(c.title, "[VigilantIQ] CVE-2026-41120 – FortiOS – priorité urgente");
  assert.ok(c.facts.some(([k, val]) => k === "Versions corrigées" && val.includes("7.2.7")));
  assert.ok(c.links.some(([, u]) => u === "https://vigilantiq.vercel.app/cve/CVE-2026-41120"));
  const text = ticketText(c);
  assert.match(text, /Remédiation :\n1\. Mettre à jour FortiOS/);
});

test("description Jira au format ADF valide", () => {
  const v = vuln();
  const doc = jiraDoc(ticketContent(v, buildRemediation(v, {}, NOW), "https://x")) as { type: string; version: number; content: { type: string }[] };
  assert.equal(doc.type, "doc");
  assert.equal(doc.version, 1);
  assert.deepEqual(doc.content.map((n) => n.type), ["paragraph", "bulletList", "heading", "orderedList", "heading", "bulletList"]);
});

test("événement SIEM : champs stables", () => {
  const v = vuln({ kev: { name: "", dateAdded: "", dueDate: "2026-11-10", ransomware: false, action: "" } });
  const e = siemEvent(v, buildRemediation(v, {}, NOW), "https://x");
  assert.equal(e.cve, "CVE-2026-41120");
  assert.equal(e.exploited, true);
  assert.equal(e.kev_due_date, "2026-11-10");
  assert.equal(e.patch_available, true);
  assert.equal(e.url, "https://x/cve/CVE-2026-41120");
});

// ---------- API ----------

test("filtres de l'API v1", () => {
  const list = [
    vuln({ id: "CVE-1", priority: "urgente", kev: { name: "", dateAdded: "", dueDate: "", ransomware: false, action: "" } }),
    vuln({ id: "CVE-2", priority: "haute", exploits: [poc("https://github.com/a/1")] }),
    vuln({ id: "CVE-3", priority: "basse", vendors: ["nginx"], products: ["nginx"], description: "nginx bug", published: "2026-10-01T00:00:00Z" }),
  ];
  const q = (s: string) => {
    const r = parseVulnQuery(new URLSearchParams(s));
    assert.ok(!("error" in r));
    return filterVulns(list, r).map((v) => v.id);
  };
  assert.deepEqual(q("min_priority=haute"), ["CVE-1", "CVE-2"]);
  assert.deepEqual(q("exploited=true"), ["CVE-1"]);
  assert.deepEqual(q("poc=true"), ["CVE-2"]);
  assert.deepEqual(q("stack=nginx"), ["CVE-3"]);
  assert.deepEqual(q("since=2026-10-20T00:00:00Z"), ["CVE-1", "CVE-2"]);
  assert.deepEqual(q("q=nginx&limit=1"), ["CVE-3"]);
  assert.ok("error" in parseVulnQuery(new URLSearchParams("priority=critique")));
  assert.ok("error" in parseVulnQuery(new URLSearchParams("since=hier")));
});

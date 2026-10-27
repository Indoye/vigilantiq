import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreVuln } from "./score.ts";
import { matchStack, parseStack } from "./stack.ts";
import { parseNvdItem } from "./sources.ts";

const kev = { name: "x", dateAdded: "2026-10-24", dueDate: "2026-11-14", ransomware: false, action: "Patch" };

test("CVE critique sans exploitation connue = haute", () => {
  const r = scoreVuln({ cvss: 9.8, epss: 0.01, kev: null });
  assert.equal(r.priority, "haute");
  assert.ok(r.score >= 55 && r.score < 75, `score ${r.score}`);
});

test("CVE exploitée activement = urgente, même avec CVSS moyen", () => {
  const r = scoreVuln({ cvss: 6.1, epss: 0.02, kev });
  assert.equal(r.priority, "urgente");
  assert.ok(r.reasons.some((x) => x.includes("KEV")));
});

test("CVSS 9.8 + EPSS élevé = urgente", () => {
  assert.equal(scoreVuln({ cvss: 9.8, epss: 0.6, kev: null }).priority, "urgente");
});

test("faible gravité = basse", () => {
  assert.equal(scoreVuln({ cvss: 3.1, epss: 0.0004, kev: null }).priority, "basse");
});

test("CVSS absent et pas d'autre signal : basse, raison expliquée", () => {
  const r = scoreVuln({ cvss: null, epss: null, kev: null });
  assert.equal(r.priority, "basse");
  assert.ok(r.reasons[0].includes("pas encore"));
});

test("score plafonné à 100", () => {
  assert.equal(scoreVuln({ cvss: 10, epss: 1, kev: { ...kev, ransomware: true } }).score, 100);
});

test("SSVC « active » sans KEV = urgente", () => {
  const r = scoreVuln({ cvss: 7.2, epss: 0.01, kev: null, ssvc: { exploitation: "active", automatable: "no", technicalImpact: "total" } });
  assert.equal(r.priority, "urgente");
});

test("exploit public et alerte CERT ajoutent des points expliqués", () => {
  const base = scoreVuln({ cvss: 8.1, epss: 0.01, kev: null });
  const r = scoreVuln({
    cvss: 8.1,
    epss: 0.01,
    kev: null,
    mentions: [
      { kind: "exploit", source: "Exploit-DB" },
      { kind: "cert", source: "CERT-FR" },
    ],
  });
  assert.equal(r.score, base.score + 15);
  assert.ok(r.reasons.includes("Code d'exploitation public"));
  assert.ok(r.reasons.includes("Signalée par CERT-FR"));
});

test("parseStack nettoie et déduplique", () => {
  assert.deepEqual(parseStack(" Nginx, fortinet\nnginx; a ,WordPress"), ["nginx", "fortinet", "wordpress"]);
});

test("matchStack : CPE et description, sans faux positif de sous-mot", () => {
  const v = { vendors: ["fortinet"], products: ["fortios"], description: "A flaw in the SSL-VPN of FortiOS allows RCE." };
  assert.deepEqual(matchStack(v, ["fortinet", "fortios", "ssl vpn", "nginx"]), ["fortinet", "fortios", "ssl vpn"]);
  const w = { vendors: [], products: [], description: "Cross-site scripting in the plugin" };
  assert.deepEqual(matchStack(w, ["ss"]), []);
});

test("parseNvdItem extrait CVSS 3.1 primaire, CPE et CWE", () => {
  const item = {
    cve: {
      id: "CVE-2026-0001",
      published: "2026-10-26T08:15:00.000",
      descriptions: [{ lang: "es", value: "x" }, { lang: "en", value: "Buffer overflow in Foo." }],
      metrics: {
        cvssMetricV31: [
          { type: "Secondary", cvssData: { baseScore: 7.5, baseSeverity: "HIGH", vectorString: "S" } },
          { type: "Primary", cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N" } },
        ],
      },
      weaknesses: [{ description: [{ lang: "en", value: "CWE-787" }, { lang: "en", value: "NVD-CWE-Other" }] }],
      configurations: [
        { nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:acme:foo_server:*:*:*:*:*:*:*:*" }] }] },
      ],
      references: [{ url: "https://acme.example/advisory" }],
    },
  };
  const r = parseNvdItem(item);
  assert.equal(r.cvss, 9.8);
  assert.equal(r.severity, "CRITICAL");
  assert.equal(r.description, "Buffer overflow in Foo.");
  assert.deepEqual(r.vendors, ["acme"]);
  assert.deepEqual(r.products, ["foo_server"]);
  assert.deepEqual(r.cwes, ["CWE-787"]);
});

import assert from "node:assert/strict";
import test from "node:test";
import { escalationsByCve, parseRepo, readCve, readFeed, readRepo } from "./sc-core.ts";

test("SecurityContext : noms de dépôts", () => {
  assert.equal(parseRepo("vercel/next.js"), "vercel/next.js");
  assert.equal(parseRepo("https://github.com/Indoye/vigilantiq.git/"), "Indoye/vigilantiq");
  assert.equal(parseRepo("github.com/a-b/c_d"), "a-b/c_d");
  assert.equal(parseRepo("../etc/passwd"), null);
  assert.equal(parseRepo("owner/.."), null);
  assert.equal(parseRepo("owner/name/extra"), null);
  assert.equal(parseRepo("owner/name?x=1"), null);
});

test("SecurityContext : lecture d'une CVE", () => {
  const c = readCve({
    found: true,
    cve: "CVE-2021-44228",
    name: "Apache Log4j2 - JNDI Injection",
    impact: "RCE",
    remediation: "Update",
    severity: "critical",
    patch_available: true,
    known_exploited_entries: [
      { list: "cisa", added_date: "2021-12-10", due_date: "2021-12-24", ransomware_use: true },
      { list: "vulncheck", added_date: "2021-12-06", ransomware_use: false },
    ],
    nuclei_templates: [{ id: "CVE-2021-44228", url: "https://github.com/projectdiscovery/nuclei-templates/x.yaml" }],
    public_exploits_total: 100,
    public_exploits_capped: true,
    public_exploits: [{ url: "http://packetstormsecurity.com/files/1", added_date: "2021-12-10" }, { url: "javascript:alert(1)" }],
    products_total: 143,
    products: [{ product: "apache:log4j", affected: [">= 2.13.0, < 2.15.0"] }],
    projects: [{ repository: "apache/logging-log4j2" }],
    index: { repositories: 331, packages: 1 },
    _meta: { dataset: "2026-11-24T22:32:04Z" },
    exploitation: { known_exploited: true, known_exploited_by: ["cisa", "vulncheck"], vulncheck_known_exploited_since: "2021-12-06", public_exploit: true, public_exploit_first_date: "2021-12-10", initial_access: false, remote: true, authentication_required: false, hackerone_reports: 668, exposed_hosts: 4739835 },
  })!;
  assert.equal(c.exploitation.ransomware, true);
  assert.equal(c.exploitation.cisaSince, "2021-12-10");
  assert.equal(c.exploitation.exposedHosts, 4739835);
  assert.equal(c.exploits.length, 1, "liens non http écartés");
  assert.equal(c.nuclei?.id, "CVE-2021-44228");
  assert.deepEqual(c.projects, ["apache/logging-log4j2"]);
  assert.equal(readCve({ found: false }), null);
});

test("SecurityContext : flux des escalades", () => {
  const list = readFeed({
    items: [
      { id: "https://api.securitycontext.com/v1/cves/CVE-2026-74253#vulncheck_known_exploited:2026-11-24", content_text: "severity critical", date_published: "2026-11-24T00:00:00Z", tags: ["vulncheck_known_exploited", "critical"] },
      { id: "https://api.securitycontext.com/v1/cves/CVE-2026-74253#public_exploit:2026-11-20", date_published: "2026-11-20T00:00:00Z", tags: ["public_exploit"] },
      { id: "https://api.securitycontext.com/v1/cves/CVE-2026-1#rejected_by_nvd:2026-11-20" },
      { id: "n'importe quoi" },
    ],
  });
  assert.equal(list.length, 2);
  assert.equal(list[0].severity, "critical");
  assert.deepEqual(escalationsByCve(list), { "CVE-2026-74253": ["vulncheck_known_exploited", "public_exploit"] });
});

test("SecurityContext : vue d'un dépôt", () => {
  const v = readRepo(
    "vercel/next.js",
    { found: true, risk_score: 74, risk_percentile: 89, severity: "medium", stars: 104439, counts: { vulnerable_dependencies_runtime: 130, public_exploit_vulns: 49, contributors_with_leak: 9 } },
    { risk: { breakdown: { known_exploited: 8, contributors: 570 }, cheapest_path: { type: "vulnerable runtime dependency", detail: "x", fix: "upgrade to a fixed version" }, entry_points: [{ type: "native library", count: 1, fix: "upgrade the wrapper package that bundles it" }] } },
    {
      summary: { packages: 2715, affected: 98, known_exploited: 0, public_exploit: 31, malicious: 0, by_severity: { critical: 11, high: 42 } },
      groups: {
        items: [
          { manifest: "a/package.json", direct_dependency: { package: "npm/x", version: "1.0.0" }, affected: 2, worst_severity: "medium", packages: [] },
          { manifest: "b/Cargo.lock", direct_dependency: { package: "cargo/reqwest", version: "0.11.6" }, affected: 9, worst_severity: "critical", packages: [{ input: "cargo/mio@0.7.14", status: "affected", fixed_version: "0.8.11", worst_severity: "critical" }, { input: "cargo/ok@1", status: "clean" }] },
        ],
      },
    },
  );
  assert.equal(v.riskScore, 74);
  assert.equal(v.upgrades[0].direct, "cargo/reqwest@0.11.6", "la plus grave d'abord");
  assert.deepEqual(v.upgrades[0].packages, [{ input: "cargo/mio@0.7.14", fixed: "0.8.11", worst: "critical" }]);
  assert.equal(v.stack?.bySeverity.critical, 11);
  assert.equal(readRepo("a/b", { found: false, candidates: [{ repository: "a/bb" }] }, null, null).candidates[0], "a/bb");
});

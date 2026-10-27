import { test } from "node:test";
import assert from "node:assert/strict";
import { cnaAffected, formatRange, nvdAffected, osvAffected } from "./versions.ts";
import { parseCveOrg } from "./cveorg.ts";
import { extractCves, parseFeed } from "./rss.ts";
import { mergeReferences } from "./references.ts";

test("formatRange couvre les cas usuels", () => {
  assert.equal(formatRange({ from: "7.0.0", to: "7.0.14" }), "7.0.0 → < 7.0.14");
  assert.equal(formatRange({ from: "7.0.0", to: "7.0.13", toIncl: true }), "7.0.0 → 7.0.13");
  assert.equal(formatRange({ from: "0", to: "2.4.1" }), "< 2.4.1");
  assert.equal(formatRange({ to: "3.0", toIncl: true }), "≤ 3.0");
  assert.equal(formatRange({ from: "5.1" }), "≥ 5.1");
  assert.equal(formatRange({}), "Toutes les versions");
});

test("nvdAffected : plages, version exacte, correctif, plateformes", () => {
  const conf = [
    {
      nodes: [
        {
          cpeMatch: [
            { vulnerable: true, criteria: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", versionStartIncluding: "7.0.0", versionEndExcluding: "7.0.14" },
            { vulnerable: true, criteria: "cpe:2.3:o:fortinet:fortios:7.2.5:*:*:*:*:*:*:*" },
            { vulnerable: false, criteria: "cpe:2.3:h:fortinet:fortigate_100f:-:*:*:*:*:*:*:*" },
          ],
        },
      ],
    },
  ];
  const r = nvdAffected(conf);
  assert.equal(r.length, 1);
  assert.equal(r[0].product, "fortios");
  assert.deepEqual(r[0].ranges, ["7.0.0 → < 7.0.14", "7.2.5"]);
  assert.deepEqual(r[0].fixed, ["7.0.14"]);
  assert.deepEqual(r[0].platforms, ["fortigate 100f"]);
});

test("cnaAffected : CVE JSON 5 (affected / unaffected / lessThan)", () => {
  const rec = {
    containers: {
      cna: {
        affected: [
          {
            vendor: "Acme",
            product: "Booking",
            defaultStatus: "unaffected",
            versions: [
              { version: "0", lessThan: "3.2.2", status: "affected", versionType: "semver" },
              { version: "4.0.0", lessThanOrEqual: "4.0.3", status: "affected" },
              { version: "4.1.0", status: "unaffected" },
            ],
          },
          { vendor: "n/a", product: "n/a", versions: [{ version: "n/a", status: "affected" }] },
        ],
      },
    },
  };
  const r = cnaAffected(rec);
  assert.equal(r.length, 1);
  assert.deepEqual(r[0].ranges, ["< 3.2.2", "4.0.0 → 4.0.3"]);
  assert.deepEqual(r[0].fixed, ["3.2.2", "4.1.0"]);
});

test("cnaAffected : contraintes au format GitHub", () => {
  const r = cnaAffected({
    containers: { cna: { affected: [{ vendor: "x", product: "lib", versions: [{ version: ">= 1.0.0, < 1.4.2", status: "affected" }, { version: "<= 0.9.8", status: "affected" }] }] } },
  });
  assert.deepEqual(r[0].ranges, ["1.0.0 → < 1.4.2", "≤ 0.9.8"]);
  assert.deepEqual(r[0].fixed, ["1.4.2"]);
});

test("osvAffected : événements introduced/fixed, plages GIT ignorées", () => {
  const osv = {
    affected: [
      {
        package: { ecosystem: "PyPI", name: "requests" },
        ranges: [
          { type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.31.0" }] },
          { type: "GIT", events: [{ introduced: "abc" }, { fixed: "def" }] },
        ],
      },
    ],
  };
  const r = osvAffected(osv);
  assert.equal(r[0].ecosystem, "PyPI");
  assert.deepEqual(r[0].ranges, ["< 2.31.0"]);
  assert.deepEqual(r[0].fixed, ["2.31.0"]);
});

test("parseCveOrg : CVSS du CNA, repli ADP, SSVC", () => {
  const rec = {
    cveMetadata: { cveId: "CVE-2026-1", state: "PUBLISHED", assignerShortName: "fortinet", datePublished: "2026-10-26T08:00:00Z" },
    containers: {
      cna: {
        descriptions: [{ lang: "en", value: "Overflow." }],
        affected: [{ vendor: "Fortinet", product: "FortiOS", versions: [{ version: "7.0.0", lessThan: "7.0.14", status: "affected" }] }],
        references: [{ url: "https://fortiguard.example/psirt", tags: ["vendor-advisory"] }],
        problemTypes: [{ descriptions: [{ cweId: "CWE-122" }] }],
      },
      adp: [
        {
          providerMetadata: { shortName: "CISA-ADP" },
          metrics: [
            { cvssV3_1: { baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N" } },
            { other: { type: "ssvc", content: { options: [{ Exploitation: "active" }, { Automatable: "yes" }, { "Technical Impact": "total" }] } } },
          ],
        },
      ],
    },
  };
  const c = parseCveOrg(rec);
  assert.equal(c.cvss, 9.8);
  assert.equal(c.cvssSource, "CISA-ADP");
  assert.deepEqual(c.ssvc, { exploitation: "active", automatable: "yes", technicalImpact: "total" });
  assert.deepEqual(c.cwes, ["CWE-122"]);
  assert.equal(c.affected[0].ranges[0], "7.0.0 → < 7.0.14");
});

test("parseFeed : RSS 2.0 et Atom, extraction des CVE", () => {
  const rss = `<?xml version="1.0"?><rss version="2.0"><channel><title>CERT-FR</title>
    <item><title>Multiples vulnérabilités dans Fortinet FortiOS</title><link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/</link>
    <pubDate>Mon, 26 Oct 2026 09:15:00 +0000</pubDate><description><![CDATA[<p>Références : CVE-2026-41120 &amp; cve-2026-41121</p>]]></description></item>
  </channel></rss>`;
  const a = parseFeed(rss, { id: "certfr", name: "CERT-FR", kind: "cert" });
  assert.equal(a.length, 1);
  assert.deepEqual(a[0].cves, ["CVE-2026-41120", "CVE-2026-41121"]);
  assert.equal(a[0].published, "2026-10-26T09:15:00.000Z");
  assert.ok(a[0].summary.includes("&"));

  const atom = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>VU#123456: Example</title>
    <link rel="alternate" href="https://kb.cert.org/vuls/id/123456"/><updated>2026-10-25T10:00:00Z</updated><summary>CVE-2026-5000</summary></entry></feed>`;
  const b = parseFeed(atom, { id: "certcc", name: "CERT/CC", kind: "cert" });
  assert.equal(b[0].link, "https://kb.cert.org/vuls/id/123456");
  assert.deepEqual(b[0].cves, ["CVE-2026-5000"]);
  assert.deepEqual(extractCves("rien ici"), []);
});

test("mergeReferences : dédoublonne, traduit, met les correctifs en premier", () => {
  const r = mergeReferences(
    [{ url: "https://a.example/blog", tags: ["Third Party Advisory"] }, { url: "https://v.example/fix", tags: ["Patch"] }],
    [{ url: "https://v.example/fix", tags: ["vendor-advisory", "x_refsource_CONFIRM"] }],
  );
  assert.equal(r[0].url, "https://v.example/fix");
  assert.deepEqual(r[0].tags, ["Correctif", "Avis éditeur"]);
  assert.deepEqual(r[1].tags, ["Avis tiers"]);
});

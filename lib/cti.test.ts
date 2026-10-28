import assert from "node:assert/strict";
import { test } from "node:test";
import { iocsToCsv, iocsToStix, stixPattern } from "./cti/export.ts";
import { containsTerm, draftEmail, draftInfostealer, draftLookalikes, matchBreaches, matchPhishing, matchRansom } from "./cti/match.ts";
import {
  brandOf,
  iocsFromFeodo,
  iocsFromOpenPhish,
  iocsFromThreatFox,
  normalizeBrand,
  normalizeDomain,
  parseBreaches,
  parseInfostealer,
  parseRansomVictims,
  parseXposed,
  type Ioc,
} from "./cti/sources.ts";
import { permutations } from "./cti/typosquat.ts";

test("domaines et marques", () => {
  assert.equal(normalizeDomain("https://www.Sonatel.SN/page?x=1"), "sonatel.sn");
  assert.equal(normalizeDomain("pas un domaine"), null);
  assert.equal(normalizeDomain("a.b"), null);
  assert.equal(brandOf("sonatel.sn"), "sonatel");
  assert.equal(brandOf("exemple.co.uk"), "exemple");
  assert.equal(brandOf("mail.orange.fr"), "orange");
  assert.equal(normalizeBrand("  Orange  Money "), "orange money");
  assert.equal(normalizeBrand("x"), null);
});

test("ransomware.live : métadonnées seulement", () => {
  const v = parseRansomVictims([
    { victim: "Echo.com", domain: "Echo.com", group: "Whitearmor", country: "de", activity: "Technology", discovered: "2026-10-28T02:10:02+00:00", attackdate: "2026-10-28T01:05:00+00:00", claim_url: "http://x.onion", description: "Contact: x@proton.me", url: "https://www.ransomware.live/id/abc" },
    { victim: "", group: "x" },
    { victim: "Acme", group: "akira", url: "http://evil.example/" },
  ]);
  assert.equal(v.length, 2);
  assert.equal(v[0].domain, "echo.com");
  assert.equal(v[0].country, "DE");
  assert.ok(!("description" in v[0]) && !JSON.stringify(v).includes("onion") && !JSON.stringify(v).includes("proton"));
  assert.equal(v[1].url, "");
  assert.equal(v[0].sector, "Technologie");
  assert.equal(parseRansomVictims([{ victim: "A", group: "b", activity: "Not Found" }])[0].sector, "");
});

test("correspondances rançongiciels, fuites, hameçonnage", () => {
  const targets = [
    { kind: "domain" as const, value: "sonatel.sn" },
    { kind: "brand" as const, value: "orange money" },
  ];
  const victims = parseRansomVictims([
    { victim: "Sonatel SA", domain: "sonatel.sn", group: "akira", url: "https://www.ransomware.live/id/1", discovered: "2026-10-27T00:00:00Z" },
    { victim: "Groupe Sonatel Mobiles", domain: "", group: "lockbit", url: "https://www.ransomware.live/id/2" },
    { victim: "Orange Money Mali", group: "qilin", url: "https://www.ransomware.live/id/3" },
    { victim: "Sonatelix Corp", group: "play", url: "https://www.ransomware.live/id/4" },
  ]);
  const rw = matchRansom(targets, victims);
  assert.deepEqual(rw.map((a) => [a.externalId, a.severity]), [
    ["rw:https://www.ransomware.live/id/1", "critique"],
    ["rw:https://www.ransomware.live/id/2", "haute"],
    ["rw:https://www.ransomware.live/id/3", "haute"],
  ]);
  assert.ok(containsTerm("Sonatel SA", "sonatel") && !containsTerm("Sonatelix", "sonatel"));

  const breaches = parseBreaches([
    { Name: "Sonatel", Title: "Sonatel", Domain: "sonatel.sn", PwnCount: 1200, AddedDate: "2026-10-01T00:00:00Z", DataClasses: ["Email addresses"] },
    { Name: "Spam", Title: "Spam", Domain: "x.com", IsSpamList: true },
    { Name: "Autre", Title: "Autre", Domain: "autre.com", PwnCount: 5, Description: "<a href='x'>Texte</a> &amp; plus" },
  ]);
  assert.equal(breaches.length, 2);
  assert.equal(breaches.find((b) => b.name === "Autre")!.description, "Texte & plus");
  const br = matchBreaches(targets, breaches);
  assert.deepEqual(br.map((a) => [a.externalId, a.severity]), [["hibp:Sonatel", "haute"]]);

  const iocs = iocsFromOpenPhish("https://sonatel-login.example.com/a\nhttps://www.sonatel.sn/vrai\nhttps://orangemoney-verif.xyz/\nnot a url\nhttps://sonatel-login.example.com/b", "2026-10-28T00:00:00Z");
  assert.equal(iocs.length, 4);
  const ph = matchPhishing(targets, iocs);
  assert.deepEqual(ph.map((a) => a.externalId), ["phish:sonatel-login.example.com", "phish:orangemoney-verif.xyz"]);
});

test("infostealers : agrégats sans URL complètes", () => {
  const s = parseInfostealer("exemple.sn", {
    total: 40,
    employees: 3,
    users: 37,
    third_parties: 1,
    last_employee_compromised: "2026-10-18T00:00:00.000Z",
    data: { employees_urls: [{ occurrence: 5, url: "https://sso.exemple.sn/adfs/ls?token=SECRET" }, { occurrence: 2, url: "https://sso.exemple.sn/" }, { occurrence: 1, url: "\"https://vpn.exemple.sn/login\"," }] },
    stealerFamilies: { total: 40, UNKNOWN: 2, Lumma: 20, RedLine: 18 },
    employeePasswords: { has_stats: true, too_weak: { perc: 20 }, weak: { perc: 10.55 } },
  });
  assert.deepEqual(s.employeeHosts, [{ host: "sso.exemple.sn", count: 7 }, { host: "vpn.exemple.sn", count: 1 }]);
  assert.ok(!JSON.stringify(s).includes("SECRET"));
  assert.deepEqual(s.families.map((f) => f.name), ["Lumma", "RedLine"]);
  assert.equal(s.weakPasswordsPct, 30.6);
  const a = draftInfostealer(s, Date.parse("2026-10-28T00:00:00Z"));
  assert.equal(a[0].severity, "critique");
  assert.equal(draftInfostealer({ ...s, employees: 0, users: 0 }).length, 0);
  assert.equal(draftInfostealer({ ...s, employees: 0 })[0].severity, "moyenne");
});

test("typosquatting : variantes", () => {
  const p = permutations("sonatel.sn");
  assert.ok(!p.includes("sonatel.sn"));
  for (const d of ["sonatel.com", "s0natel.sn", "sonatl.sn", "sonnatel.sn", "osnatel.sn", "sonatel-login.sn", "sona-tel.sn"]) assert.ok(p.includes(d), d);
  assert.ok(p.length <= 140 && new Set(p).size === p.length);
  assert.ok(p.every((d) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)));
  assert.deepEqual(permutations("exemple.co.uk").slice(0, 1), ["exemple.com"]);
  const al = draftLookalikes("sonatel.sn", [{ domain: "s0natel.sn", ips: ["1.2.3.4"], mx: true }]);
  assert.equal(al[0].severity, "haute");
});

test("e-mail exposé", () => {
  assert.deepEqual(parseXposed({ breaches: [["A", "B", "A"]] }), ["A", "B"]);
  assert.deepEqual(parseXposed({ Error: "Not found" }), []);
  assert.equal(draftEmail("Moi@Ex.sn", ["A"])[0].externalId, "email:moi@ex.sn:A");
});

test("IOC : flux et exports", () => {
  const feodo = iocsFromFeodo([{ ip_address: "1.2.3.4", port: 443, status: "online", country: "US", malware: "QakBot", first_seen: "2026-10-01 10:00:00" }]);
  assert.equal(feodo[0].value, "1.2.3.4:443");
  assert.equal(feodo[0].firstSeen, "2026-10-01T10:00:00.000Z");
  const tf = iocsFromThreatFox({ data: [{ id: "9", ioc: "evil.example", ioc_type: "domain", threat_type_desc: "Botnet C&C", malware_printable: "Cobalt Strike", first_seen: "2026-10-27 08:00:00 UTC", confidence_level: 90, tags: ["cs"] }, { ioc: "x", ioc_type: "inconnu" }] });
  assert.equal(tf.length, 1);
  assert.equal(tf[0].firstSeen, "2026-10-27T08:00:00.000Z");
  const items: Ioc[] = [...feodo, ...tf, { type: "sha256", value: "a".repeat(64), threat: "x", malware: "", source: "s", firstSeen: null, confidence: null, tags: [], ref: "" }, { type: "url", value: "=cmd|' /C calc'!A0", threat: "t", malware: "", source: "s", firstSeen: null, confidence: null, tags: [], ref: "" }];
  const csv = iocsToCsv(items);
  assert.ok(csv.startsWith("type,valeur,"));
  assert.ok(csv.includes("'=cmd"));
  assert.equal(stixPattern(feodo[0]), "[network-traffic:dst_ref.value = '1.2.3.4' AND network-traffic:dst_port = 443]");
  assert.equal(stixPattern(items[2]), `[file:hashes.'SHA-256' = '${"a".repeat(64)}']`);
  const b = iocsToStix(items, "2026-10-28T00:00:00.000Z") as { type: string; objects: { type: string; id: string }[] };
  assert.equal(b.type, "bundle");
  assert.equal(b.objects.filter((o) => o.type === "indicator").length, 4);
  assert.ok(b.objects.every((o) => /^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(o.id)));
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { countryName, flag, zoneLabel, zoneMembers } from "./geo/zones.ts";
import { mergeFlows, parseAttackPairs, parseFeodo, parseTopPorts } from "./threatmap.ts";

test("Radar : paires origine → cible", () => {
  const r = {
    meta: {},
    top_0: [
      { originCountryAlpha2: "CN", targetCountryAlpha2: "US", value: "5.2", rank: 1 },
      { originCountryAlpha2: "ru", targetCountryAlpha2: "de", value: "3.1" },
      { originCountryAlpha2: "XX1", targetCountryAlpha2: "US", value: "1" },
      { originCountryAlpha2: "FR", targetCountryAlpha2: "SN", value: "0" },
    ],
  };
  assert.deepEqual(parseAttackPairs(r, "L7"), [
    { from: "CN", to: "US", value: 5.2, layer: "L7" },
    { from: "RU", to: "DE", value: 3.1, layer: "L7" },
  ]);
  assert.deepEqual(parseAttackPairs(null, "L3"), []);
  assert.deepEqual(parseAttackPairs({ autre: [{ originLocationAlpha2: "NL", targetLocationAlpha2: "FR", value: 2 }] }, "L3"), [{ from: "NL", to: "FR", value: 2, layer: "L3" }]);
});

test("fusion des flux : doublons et tri", () => {
  const m = mergeFlows([
    { from: "CN", to: "US", value: 2, layer: "L7" },
    { from: "CN", to: "US", value: 5, layer: "L7" },
    { from: "CN", to: "US", value: 1, layer: "L3" },
    { from: "RU", to: "DE", value: 3, layer: "L7" },
  ]);
  assert.deepEqual(m.map((f) => `${f.layer}:${f.from}>${f.to}=${f.value}`), ["L7:CN>US=5", "L7:RU>DE=3", "L3:CN>US=1"]);
});

test("Feodo Tracker : C2 par pays", () => {
  const { c2, total } = parseFeodo([
    { country: "US", status: "online", malware: "QakBot" },
    { country: "US", status: "offline", malware: "QakBot" },
    { country: "US", status: "offline", malware: "Emotet" },
    { country: "SN", status: "online", malware: "Emotet" },
    { country: null, malware: "x" },
  ]);
  assert.equal(total, 4);
  assert.deepEqual(c2[0], { cc: "US", count: 3, online: 1, malware: [{ name: "QakBot", count: 2 }, { name: "Emotet", count: 1 }] });
  assert.equal(c2[1].cc, "SN");
  assert.deepEqual(parseFeodo({ erreur: 1 }), { c2: [], total: 0 });
});

test("DShield : ports les plus attaqués", () => {
  const { ports, date } = parseTopPorts({ 0: { rank: 1, targetport: 23, records: 10, targets: 5, sources: 2 }, 1: { targetport: "22", records: "20", targets: 1, sources: 1 }, limit: 10, date: "2026-10-27" });
  assert.equal(date, "2026-10-27");
  assert.deepEqual(ports.map((p) => p.port), [22, 23]);
});

test("zones et pays", () => {
  assert.equal(zoneMembers("monde"), null);
  const ao = zoneMembers("afrique-ouest")!;
  assert.ok(ao.has("SN") && ao.has("CI") && ao.has("NG") && !ao.has("MA"));
  assert.ok(zoneMembers("afrique-nord")!.has("MA"));
  assert.ok(zoneMembers("europe")!.has("FR") && !zoneMembers("europe")!.has("US"));
  assert.ok(zoneMembers("moyen-orient")!.has("SA") && !zoneMembers("asie")!.has("SA"));
  assert.deepEqual([...zoneMembers("pays:sn")!], ["SN"]);
  assert.equal(zoneLabel("pays:SN"), "Sénégal");
  assert.equal(countryName("de"), "Allemagne");
  assert.equal(flag("FR"), "🇫🇷");
});

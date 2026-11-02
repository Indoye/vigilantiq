import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOutages, parseSummary, splitPairs } from "./threatfocus.ts";

test("paires d'attaque : entrantes et sortantes du pays", () => {
  const r = splitPairs(
    [
      { from: "US", to: "SN", value: 30, layer: "L7" },
      { from: "US", to: "SN", value: 12, layer: "L7" },
      { from: "FR", to: "SN", value: 20, layer: "L3" },
      { from: "SN", to: "SN", value: 50, layer: "L7" },
      { from: "SN", to: "MA", value: 5, layer: "L7" },
      { from: "DE", to: "FR", value: 99, layer: "L7" },
    ],
    "SN",
  );
  assert.deepEqual(r.incoming, [
    { cc: "US", value: 30, layer: "L7" },
    { cc: "FR", value: 20, layer: "L3" },
  ]);
  assert.deepEqual(r.outgoing, [{ cc: "MA", value: 5, layer: "L7" }]);
});

test("résumés Radar et coupures", () => {
  assert.deepEqual(parseSummary({ summary_0: { DDOS: "61.5", WAF: "30.1", other: "8.4", API_SHIELD: "0" } }), [
    { key: "DDOS", value: 61.5 },
    { key: "WAF", value: 30.1 },
  ]);
  assert.deepEqual(parseSummary(null), []);
  const o = parseOutages(
    {
      annotations: [
        { startDate: "2026-10-20T10:00:00Z", endDate: "2026-10-20T14:00:00Z", locations: ["SN"], asnsDetails: [{ asn: "8346", name: "SONATEL-AS" }], outage: { outageCause: "POWER_OUTAGE", outageType: "REGIONAL" }, description: "x" },
        { startDate: "2026-10-25T10:00:00Z", locations: ["GM"], outage: {} },
        { startDate: "2026-10-28T10:00:00Z", locations: ["SN"], outage: { outageCause: "CABLE_CUT", outageType: "NATIONWIDE" } },
      ],
    },
    "SN",
  );
  assert.equal(o.length, 2);
  assert.equal(o[0].cause, "CABLE_CUT");
  assert.deepEqual(o[1].networks, ["SONATEL-AS"]);
});

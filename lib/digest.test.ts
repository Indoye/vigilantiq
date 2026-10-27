import { test } from "node:test";
import assert from "node:assert/strict";
import { selectForDigest } from "./digest.ts";
import type { Feed, Vuln } from "./types.ts";

const v = (id: string, priority: Vuln["priority"], extra: Partial<Vuln> = {}): Vuln => ({
  id, published: "", description: "", cvss: null, cvssVersion: null, cvssSource: null, severity: null, vector: null,
  epss: null, epssPercentile: null, kev: null, ssvc: null, vendors: [], products: [], cwes: [], references: [],
  affected: [], mentions: [], origin: "nvd", score: 0, priority, reasons: [], ...extra,
});

const kev = { name: "", dateAdded: "", dueDate: "", ransomware: false, action: "" };
const feed: Feed = {
  generatedAt: "", windowHours: 24, errors: [], aiEnabled: false, sources: [],
  vulns: [
    v("CVE-1", "urgente", { kev }),
    v("CVE-2", "haute"),
    v("CVE-3", "moyenne", { products: ["nginx"] }),
    v("CVE-4", "moyenne"),
    v("CVE-5", "basse", { products: ["nginx"] }),
  ],
};
const ids = (x: { id: string }[]) => x.map((y) => y.id);

test("priorité minimale « haute » : urgentes, hautes et la stack à partir de moyenne", () => {
  assert.deepEqual(ids(selectForDigest(feed, "nginx", { minPriority: "haute" })), ["CVE-1", "CVE-2", "CVE-3"]);
});

test("seulement ma stack : la stack + les failles exploitées", () => {
  assert.deepEqual(ids(selectForDigest(feed, "nginx", { minPriority: "moyenne", stackOnly: true })), ["CVE-1", "CVE-3"]);
});

test("les CVE traitées ou non concernées sont exclues", () => {
  assert.deepEqual(ids(selectForDigest(feed, "", { minPriority: "moyenne", closed: new Set(["CVE-1", "CVE-4"]) })), ["CVE-2", "CVE-3"]);
});

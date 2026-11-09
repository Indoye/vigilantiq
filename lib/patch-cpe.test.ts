import assert from "node:assert/strict";
import test from "node:test";
import { bestCandidate, normalizeName } from "./patch/cpematch.ts";

test("cpe : normalisation des noms affichés", () => {
  assert.equal(normalizeName("Zoom Workplace (64-bit) 6.2.5"), "zoom workplace");
  assert.equal(normalizeName("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135"), "microsoft visual c++ redistributable");
  assert.equal(normalizeName("Python 3.12.4 (64-bit)"), "python");
  assert.equal(normalizeName("Cisco Secure Client - AnyConnect VPN 5.1.2.42"), "cisco secure client anyconnect vpn");
});

const C = (vendor: string, product: string, title: string) => ({ vendor, product, title });

test("cpe : bon produit choisi, éditeur cohérent", () => {
  const r = bestCandidate("Zoom Workplace (64-bit)", "Zoom Video Communications, Inc.", [
    C("zoom", "workplace_desktop", "Zoom Workplace Desktop 6.2.5"),
    C("zoom", "zoom", "Zoom 5.0"),
    C("acme", "workplace_suite", "ACME Workplace Suite 1.0"),
  ]);
  assert.ok(r);
  assert.equal(r.vendor, "zoom");
  assert.ok(r.confidence >= 72, String(r.confidence));
});

test("cpe : python reconnu", () => {
  const r = bestCandidate("Python 3.12.4 (64-bit)", "Python Software Foundation", [C("python", "python", "Python 3.12.4"), C("python", "pillow", "Python Pillow 10")]);
  assert.equal(r?.product, "python");
  assert.ok((r?.confidence ?? 0) >= 72);
});

test("cpe : pas d'association hasardeuse", () => {
  const r = bestCandidate("Mon Outil Interne Paie", "Entreprise SN", [C("paie", "paie_pro", "Paie Pro 2"), C("outil", "outil_web", "Outil Web 1.0")]);
  assert.ok(!r || r.confidence < 72, JSON.stringify(r));
});

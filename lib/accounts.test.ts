import assert from "node:assert/strict";
import { test } from "node:test";
import { belongsTo, draftAccount, extractEmails, normalizeEmail, parseBreachAnalytics, parseStealers } from "./cti/accounts.ts";

test("adresses : extraction et appartenance au domaine", () => {
  assert.deepEqual(extractEmails("Nom;Mail\nAwa;Awa.Ndiaye@Entreprise.SN\n<moussa@mail.entreprise.sn>, x@autre.com, pas-une-adresse, awa.ndiaye@entreprise.sn"), [
    "awa.ndiaye@entreprise.sn",
    "moussa@mail.entreprise.sn",
    "x@autre.com",
  ]);
  assert.equal(normalizeEmail("mailto:A@B.co"), "a@b.co");
  assert.ok(belongsTo("moussa@mail.entreprise.sn", "entreprise.sn"));
  assert.ok(!belongsTo("x@fauxentreprise.sn", "entreprise.sn"));
});

test("XposedOrNot : détail des fuites", () => {
  const b = parseBreachAnalytics({
    ExposedBreaches: {
      breaches_details: [
        { breach: "Ancienne", domain: "a.com", xposed_date: "2016", xposed_data: "Email addresses;Passwords", password_risk: "plaintext", xposed_records: 1000, industry: "Retail", details: "x" },
        { breach: "Recente", domain: "b.com", xposed_date: "2026", xposed_data: "Email addresses;Names", password_risk: "bizarre", added: "2026-10-02T12:15:46+00:00" },
      ],
    },
  });
  assert.deepEqual(b.map((x) => x.name), ["Recente", "Ancienne"]);
  assert.equal(b[1].passwordRisk, "plaintext");
  assert.equal(b[0].passwordRisk, "unknown");
  assert.deepEqual(b[1].dataTypes, ["Email addresses", "Passwords"]);
  assert.deepEqual(parseBreachAnalytics({ Error: "Not found" }), []);
});

test("Hudson Rock : métadonnées sans mot de passe, identifiant ni IP", () => {
  const s = parseStealers({
    stealers: [
      { date_compromised: "2026-10-27T00:00:00.000Z", computer_name: "PC-COMPTA", operating_system: "Windows 11", malware_path: "C:\\x.exe", antiviruses: ["Windows Defender"], ip: "106.215.***.**", top_passwords: ["S*******3"], top_logins: ["b***@gmail.com"], total_corporate_services: 3, total_user_services: 31 },
    ],
  });
  assert.deepEqual(s, [{ date: "2026-10-27T00:00:00.000Z", computer: "PC-COMPTA", os: "Windows 11", antiviruses: ["Windows Defender"], corporateServices: 3, userServices: 31 }]);
  const txt = JSON.stringify(s);
  for (const leak of ["S*******3", "gmail", "106.215", "x.exe"]) assert.ok(!txt.includes(leak), leak);
  assert.deepEqual(parseStealers({ message: "not associated", stealers: [] }), []);
});

test("alertes par compte", () => {
  const breaches = parseBreachAnalytics({ ExposedBreaches: { breaches_details: [{ breach: "Shop", xposed_data: "Email addresses;Passwords", password_risk: "easytocrack", xposed_date: "2025" }, { breach: "News", xposed_data: "Email addresses", password_risk: "unknown", xposed_date: "2024" }] } });
  const stealers = parseStealers({ stealers: [{ date_compromised: "2026-10-01T00:00:00Z", computer_name: "PC" }] });
  const a = draftAccount("awa@entreprise.sn", breaches, stealers);
  assert.deepEqual(a.map((x) => [x.externalId, x.severity]), [
    ["acct-stealer:awa@entreprise.sn:2026-10-01T00:00:00Z", "critique"],
    ["acct-breach:awa@entreprise.sn:Shop", "haute"],
    ["acct-breach:awa@entreprise.sn:News", "moyenne"],
  ]);
  assert.ok(a.every((x) => x.watchValue === "entreprise.sn" && x.source === "account"));
});

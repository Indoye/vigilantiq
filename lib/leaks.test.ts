import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ingestKey,
  isLookalike,
  keyMatches,
  keyedHash,
  leakScore,
  maskEmail,
  minimizeIndicator,
  mispToEvents,
  newSalt,
  parseIncoming,
  severityOf,
  signBody,
  stixToEvents,
  verifySignature,
} from "./cti/leaks.ts";

const PEPPER = "poivre-de-test";

test("minimisation : aucun secret ni identifiant en clair", () => {
  const { events, rejected } = parseIncoming(
    {
      events: [
        {
          title: "Base clients Entreprise SN à vendre",
          actor: "x_seller",
          victim: "Entreprise SN",
          victim_domain: "https://www.entreprise.sn",
          posted_at: "2026-10-30T10:00:00Z",
          data_classes: ["Combolist", "phones"],
          price: "500 $",
          reference: "http://exemple.onion/t/123",
          champ_inconnu: "ignoré",
          indicators: [
            { type: "email", value: "Awa.Diop@entreprise.sn", password: "Secret123!", phone: "+221770000000" },
            { value: "admin@entreprise.sn", cookie: "SESSID=abc" },
            "jdoe",
            { type: "email", value: "pas-un-email" },
            { type: "ip", value: "196.1.95.12" },
          ],
        },
      ],
    },
    7,
    PEPPER,
  );
  assert.equal(events.length, 1);
  const e = events[0];
  const dump = JSON.stringify(e);
  for (const s of ["Secret123", "SESSID", "770000000", "awa.diop", "Awa.Diop", "jdoe", "95.12", "champ_inconnu"]) assert.ok(!dump.includes(s), `fuite de « ${s} »`);
  assert.equal(e.victimDomain, "entreprise.sn");
  assert.deepEqual(e.dataClasses, ["cookies", "credentials", "emails", "passwords", "pii"]);
  assert.equal(e.indicators.length, 4);
  const awa = e.indicators[0];
  assert.equal(awa.kind, "email");
  assert.equal(awa.domain, "entreprise.sn");
  assert.equal(awa.masked, "a••••••p@entreprise.sn");
  assert.equal(awa.valueHash, keyedHash(PEPPER, "email", "awa.diop@entreprise.sn"));
  assert.ok(awa.hasPassword && awa.hasPii && !awa.hasCookie);
  assert.ok(e.indicators[1].hasCookie);
  assert.equal(e.indicators[2].kind, "username");
  assert.equal(e.indicators[3].masked, "196.1.•.•");
  assert.match(rejected[0], /1 identifiant/);
});

test("validation : titre obligatoire, limites, dédoublonnage", () => {
  assert.equal(parseIncoming({ events: [{ victim: "x" }] }, 1, PEPPER).events.length, 0);
  assert.match(parseIncoming({ events: Array(101).fill({ title: "t" }) }, 1, PEPPER).rejected[0], /100/);
  const a = parseIncoming({ title: "Même fuite", indicators: ["a@b.sn", "A@B.SN"] }, 1, PEPPER).events[0];
  assert.equal(a.indicators.length, 1);
  const b = parseIncoming({ title: "même FUITE" }, 2, PEPPER).events[0];
  assert.equal(a.evidenceHash, b.evidenceHash, "même annonce vue par deux sources = même empreinte");
  const c = parseIncoming({ title: "x", external_id: "42" }, 3, PEPPER).events[0];
  assert.notEqual(c.evidenceHash, parseIncoming({ title: "x", external_id: "42" }, 4, PEPPER).events[0].evidenceHash);
  assert.equal(minimizeIndicator({ type: "domain", value: "https://Login.Entreprise.sn/x" }, PEPPER)?.domain, "login.entreprise.sn");
  assert.equal(maskEmail("ab@x.sn"), "a@x.sn");
});

test("clés d'ingestion et signature", () => {
  const salt = newSalt();
  const key = ingestKey("secret", 12, salt);
  assert.match(key, /^vqk_12_/);
  assert.ok(keyMatches("secret", key, salt));
  assert.ok(!keyMatches("autre-secret", key, salt));
  assert.ok(!keyMatches("secret", key, newSalt()), "sel changé = clé révoquée");
  assert.ok(!keyMatches("secret", key.slice(0, -1) + "x", salt));
  const now = 1_800_000_000_000;
  const ts = String(now / 1000);
  const body = '{"title":"x"}';
  assert.equal(verifySignature(key, ts, body, signBody(key, ts, body), now), null);
  assert.match(verifySignature(key, ts, body + " ", signBody(key, ts, body), now) ?? "", /invalide/);
  assert.match(verifySignature(key, String(now / 1000 - 600), body, signBody(key, String(now / 1000 - 600), body), now) ?? "", /fenêtre/);
  assert.match(verifySignature(key, null, body, null, now) ?? "", /obligatoires/);
});

test("score de gravité", () => {
  const now = Date.parse("2026-11-02T00:00:00Z");
  const hot = leakScore({ reliability: "B", date: "2026-10-31", classes: ["cookies"], count: 120, status: "confirmed" }, now);
  const claimed = leakScore({ reliability: "F", date: "2026-10-31", classes: ["emails"], count: 1, status: "claimed" }, now);
  const old = leakScore({ reliability: "B", date: "2024-01-01", classes: ["cookies"], count: 120, status: "confirmed" }, now);
  assert.ok(hot >= 85 && severityOf(hot) === "critique");
  assert.ok(claimed < 20 && severityOf(claimed) === "info");
  assert.ok(old < hot);
  assert.equal(leakScore({ reliability: "A", date: null, classes: [], count: 5, status: "false_positive" }, now), 0);
});

test("domaines ressemblants", () => {
  assert.ok(isLookalike("entreprise.com", "entreprise.sn"));
  assert.ok(isLookalike("entrepirse.sn", "entreprise.sn"));
  assert.ok(isLookalike("entrepr1se.sn", "entreprise.sn"));
  assert.ok(isLookalike("entreprise-sn.sn", "entreprisesn.sn"));
  assert.ok(!isLookalike("mail.entreprise.sn", "entreprise.sn"));
  assert.ok(!isLookalike("google.com", "entreprise.sn"));
  assert.ok(!isLookalike("abc.com", "abd.sn"), "noms trop courts");
});

test("MISP et STIX 2.1 → format d'ingestion", () => {
  const misp = mispToEvents({
    response: [
      {
        Event: {
          uuid: "u-1",
          info: "Fuite Entreprise SN sur BreachForums",
          date: "2026-10-30",
          Orgc: { name: "CERT-SN" },
          Tag: [{ name: 'circl:incident-classification="information-leak"' }],
          Attribute: [
            { type: "email-src", value: "a@entreprise.sn" },
            { type: "comment", value: "ignoré" },
          ],
          Object: [{ Attribute: [{ type: "domain|ip", value: "entreprise.sn|1.2.3.4" }] }],
        },
      },
    ],
  });
  assert.equal(misp[0].external_id, "misp:u-1");
  assert.deepEqual(misp[0].indicators, [
    { type: "email", value: "a@entreprise.sn" },
    { type: "domain", value: "entreprise.sn" },
  ]);
  const stix = stixToEvents({
    objects: [
      { type: "report", id: "report--1", name: "Comptes en vente", published: "2026-10-29T00:00:00Z", object_refs: ["threat-actor--1", "indicator--1", "observed-data--1", "identity--1"], labels: ["credentials"] },
      { type: "threat-actor", id: "threat-actor--1", name: "Vendeur X" },
      { type: "identity", id: "identity--1", name: "Entreprise SN" },
      { type: "indicator", id: "indicator--1", pattern: "[email-addr:value = 'b@entreprise.sn'] OR [domain-name:value = 'entreprise.sn']" },
      { type: "observed-data", id: "observed-data--1", object_refs: ["email-addr--1"] },
      { type: "email-addr", id: "email-addr--1", value: "c@entreprise.sn" },
    ],
  });
  assert.equal(stix.length, 1);
  assert.equal(stix[0].actor, "Vendeur X");
  assert.equal(stix[0].victim, "Entreprise SN");
  assert.equal((stix[0].indicators as unknown[]).length, 3);
  const parsed = parseIncoming({ events: [...misp, ...stix] }, 1, PEPPER);
  assert.equal(parsed.events.length, 2);
  assert.equal(parsed.events[1].indicators.length, 3);
});

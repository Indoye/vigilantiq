import assert from "node:assert/strict";
import test from "node:test";
import { emailHash, isOnionUrl, redact } from "./darkweb/redact.ts";

const S = "secret-de-test";

test("darkweb : e-mails remplacés par le domaine, empreinte conservée", () => {
  const r = redact("Contact: jean.dupont@banque.sn et admin@exemple.com", S);
  assert.ok(!r.text.includes("jean.dupont"));
  assert.ok(r.text.includes("[e-mail @banque.sn]"));
  assert.deepEqual(r.emailDomains.sort(), ["banque.sn", "exemple.com"]);
  assert.ok(r.emailHashes.includes(emailHash("Jean.Dupont@banque.sn", S)));
  assert.equal(r.counts.emails, 2);
});

test("darkweb : combos identifiant:mot de passe et secrets libellés masqués", () => {
  const r = redact("dump:\nalice@corp.sn:Sup3rS3cret!\nbob99;hunter22\npassword=Azerty123 token: abcdefghij", S);
  assert.ok(!/Sup3rS3cret|hunter22|Azerty123|abcdefghij/.test(r.text), r.text);
  assert.ok(r.counts.credentials >= 2);
  assert.ok(r.emailDomains.includes("corp.sn"));
});

test("darkweb : clés d'API, JWT, clés privées, hash masqués", () => {
  const txt = [
    "AKIAABCDEFGHIJKLMNOP",
    "ghp_" + "a".repeat(36),
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXRlc3Q",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
    "5f4dcc3b5aa765d61d8327deb882cf99",
    "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012",
  ].join("\n");
  const r = redact(txt, S);
  assert.ok(!/AKIA|ghp_|eyJhbG|MIIEow|5f4dcc|\$2b\$/.test(r.text), r.text);
  assert.ok(r.counts.secrets >= 6);
});

test("darkweb : téléphones, cartes valides, IBAN et IP masqués ; années et prix conservés", () => {
  const r = redact("Appelez +221 77 123 45 67. CB 4111 1111 1111 1111. IBAN FR76 3000 6000 0112 3456 7890 189. Serveur 192.168.1.10. Vendu en 2024 pour 1500 USD.", S);
  assert.ok(!/77 123|4111|FR76|192\.168/.test(r.text), r.text);
  assert.ok(r.text.includes("2024") && r.text.includes("1500"));
  assert.equal(r.counts.cards, 1);
  assert.equal(r.counts.ips, 1);
});

test("darkweb : portefeuilles conservés comme indicateurs", () => {
  const r = redact("BTC bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq ETH 0x52908400098527886E0F7030069857D2E4169EE7", S);
  assert.ok(r.wallets.includes("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
  assert.ok(r.wallets.includes("0x52908400098527886E0F7030069857D2E4169EE7"));
  assert.ok(r.text.includes("0x52908400098527886E0F7030069857D2E4169EE7"));
});

test("darkweb : seules les adresses .onion v3 sont acceptées comme départ", () => {
  assert.ok(isOnionUrl("http://xjfbpuj56rdazx4iolylxplbvyft2onuerjeimlcqwaihp3s6r4xebqd.onion/"));
  assert.ok(!isOnionUrl("https://exemple.com"));
  assert.ok(!isOnionUrl("http://127.0.0.1/"));
  assert.ok(!isOnionUrl("http://abc.onion/"));
});

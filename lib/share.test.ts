import assert from "node:assert/strict";
import { test } from "node:test";
import { sharePath, shareToken, verifyShareToken } from "./share.ts";
import { networkUrl, shareEmailBody, shareShortText, shareTitle, type ShareInfo } from "./sharetext.ts";

process.env.BETTER_AUTH_SECRET = "secret-de-test-assez-long-pour-hmac";

const info: ShareInfo = { id: "CVE-2026-41120", product: "Exchange Server", priority: "urgente", score: 92, cvss: 9.8, kev: true, poc: 3, summary: "Exécution de code à distance sans authentification." };

test("jeton de partage : stable, lié à la CVE, vérifié", () => {
  const t = shareToken("cve-2026-41120");
  assert.equal(t, shareToken("CVE-2026-41120"));
  assert.equal(t!.length, 16);
  assert.ok(verifyShareToken("CVE-2026-41120", t!));
  assert.ok(!verifyShareToken("CVE-2026-41121", t!));
  assert.ok(!verifyShareToken("CVE-2026-41120", "x".repeat(16)));
  assert.ok(!verifyShareToken("CVE-2026-41120", "court"));
  assert.equal(sharePath("CVE-2026-41120"), `/partage/CVE-2026-41120/${t}`);
});

test("textes de partage", () => {
  assert.equal(shareTitle(info), "CVE-2026-41120 · Exchange Server : priorité urgente (92/100)");
  const x = shareShortText(info);
  assert.ok(x.includes("CVSS 9,8") && x.includes("CISA KEV"));
  assert.ok(x.length + 24 <= 280);
  const long = shareShortText({ ...info, product: "P".repeat(400) });
  assert.ok(long.length + 24 <= 280);
  const body = shareEmailBody({ ...info, kev: false }, "https://ex.test/partage/x/y");
  assert.match(body, /3 codes d'exploitation publics/);
  assert.match(body, /Fiche complète : https:\/\/ex\.test\/partage\/x\/y$/);
});

test("liens des réseaux", () => {
  const u = "https://vigilantiq.vercel.app/partage/CVE-2026-41120/abc";
  const e = encodeURIComponent(u);
  assert.equal(networkUrl("linkedin", info, u), `https://www.linkedin.com/sharing/share-offsite/?url=${e}`);
  assert.ok(networkUrl("x", info, u).startsWith("https://x.com/intent/post?text=") && networkUrl("x", info, u).endsWith(`&url=${e}`));
  assert.ok(networkUrl("reddit", info, u).startsWith(`https://www.reddit.com/submit?url=${e}&title=`));
  const m = networkUrl("email", info, u);
  assert.ok(m.startsWith("mailto:?subject="));
  assert.ok(decodeURIComponent(m).includes(u));
});

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Ioc } from "./cti/sources.ts";
import { agentKey, agentKeyMatches, buildIndex, extractEvent, hunt, isPublicIp, newSalt, normDomain, parseAgentPayload, seal, unseal } from "./hunt/core.ts";
import { shellAgent } from "./hunt/scripts.ts";

const ioc = (type: Ioc["type"], value: string, threat: string, source = "abuse.ch ThreatFox"): Ioc => ({ type, value, threat, malware: "Démo", source, firstSeen: null, confidence: 90, tags: [], ref: "" });
const IDX = buildIndex([
  ioc("ip:port", "203.0.113.50:443", "Serveur de commande (C2) de botnet", "abuse.ch Feodo Tracker"),
  ioc("domain", "evil-c2.example", "botnet_cc"),
  ioc("url", "https://phish.example.net/login", "Page d’hameçonnage", "OpenPhish"),
  ioc("sha256", "a".repeat(64), "payload"),
]);

test("agent : lecture du protocole texte, IP privées ignorées", () => {
  const p = parseAgentPayload(
    [
      "host\tPC-COMPTA\tMicrosoft Windows 11 Pro\t192.168.1.20",
      "conn\t203.0.113.50\t443\tsvchost",
      "conn\t192.168.1.1\t53\tsvchost",
      "conn\t::ffff:198.51.100.7\t8080\tchrome",
      "dns\tAPI.Evil-C2.Example.",
      "dns\tsvchost.exe",
      `proc\tupdater\tC:\\Temp\\updater.exe\t${"A".repeat(64)}`,
      "inconnu\tx",
    ].join("\n"),
  );
  assert.equal(p.host.name, "PC-COMPTA");
  assert.equal(p.host.ip, "192.168.1.20");
  assert.deepEqual(
    p.obs.map((o) => `${o.kind}:${o.value}`),
    ["ip:203.0.113.50", "ip:198.51.100.7", "domain:api.evil-c2.example", `sha256:${"a".repeat(64)}`],
  );
  assert.ok(!isPublicIp("10.1.2.3") && !isPublicIp("100.64.0.1") && isPublicIp("8.8.8.8"));
  assert.equal(normDomain("rapport.pdf"), null);
});

test("chasse : IOC, exfiltration, ressemblants, Tor, tunnel DNS", () => {
  const { obs } = parseAgentPayload(
    [
      "conn\t203.0.113.50\t443\tsvchost",
      "conn\t198.51.100.9\t9001\ttor",
      "dns\tapi.evil-c2.example",
      "dns\tphish.example.net",
      "dns\tfiles.gofile.io",
      "dns\tentrepr1se.sn",
      "dns\tdiscord.com",
      `proc\tupdater\tC:\\Temp\\updater.exe\t${"a".repeat(64)}`,
      ...Array.from({ length: 9 }, (_, i) => `dns\t${"k3j9x7q2m8v4z1w6p0r5t2y8u3i9o1a" + i}.tunnel.example`),
    ].join("\n"),
  );
  const f = hunt(obs, IDX, { ownDomains: ["entreprise.sn"] });
  const by = (k: string) => f.filter((x) => x.kind === k).map((x) => `${x.indicator}|${x.severity}`);
  assert.deepEqual(by("ioc").sort(), ["203.0.113.50|critique", `${"a".repeat(64)}|critique`, "api.evil-c2.example|critique", "phish.example.net|moyenne"].sort());
  assert.deepEqual(by("exfiltration"), ["files.gofile.io|moyenne"], "discord.com seul n'est pas un signal");
  assert.deepEqual(by("ressemblant"), ["entrepr1se.sn|haute"]);
  assert.deepEqual(by("tor"), ["198.51.100.9|haute"]);
  assert.deepEqual(by("tunnel_dns"), ["tunnel.example|haute"]);
});

test("événements SIEM : ECS, Wazuh, Sysmon, Splunk", () => {
  const ecs = extractEvent({ host: { name: "srv-web" }, destination: { ip: "203.0.113.50", bytes: 5 }, dns: { question: { name: "evil-c2.example" } }, process: { name: "curl" } });
  assert.equal(ecs.host, "srv-web");
  assert.deepEqual(ecs.obs.map((o) => o.kind).sort(), ["domain", "ip"]);
  const wazuh = extractEvent({ agent: { name: "pc-rh" }, data: { srcip: "10.0.0.5", dstip: "198.51.100.7", win: { eventdata: { hashes: `SHA256=${"B".repeat(64)},MD5=${"c".repeat(32)}` } } } });
  assert.equal(wazuh.host, "pc-rh");
  assert.deepEqual(wazuh.obs.map((o) => o.kind).sort(), ["ip", "md5", "sha256"]);
  const splunk = extractEvent({ "host": "fw01", "dest_ip": "203.0.113.50", "url": "https://phish.example.net/login?x=1" });
  assert.equal(splunk.host, "fw01");
  assert.ok(splunk.obs.some((o) => o.kind === "url") && splunk.obs.some((o) => o.kind === "domain" && o.value === "phish.example.net"));
});

test("clés d'agent et chiffrement des identifiants SIEM", () => {
  const salt = newSalt();
  const k = agentKey("secret", 4, salt);
  assert.ok(agentKeyMatches("secret", k, salt));
  assert.ok(!agentKeyMatches("secret", k, newSalt()));
  assert.ok(!agentKeyMatches("autre", k, salt));
  const s = seal("secret", '{"kind":"basic","password":"x"}');
  assert.ok(!s.includes("password"));
  assert.equal(unseal("secret", s), '{"kind":"basic","password":"x"}');
  assert.throws(() => unseal("autre", s));
});

test("script shell de l'agent : syntaxe valide", () => {
  const dir = mkdtempSync(join(tmpdir(), "vq-"));
  const f = join(dir, "agent.sh");
  writeFileSync(f, shellAgent("https://exemple.sn/api/v1/telemetrie", "vqa_1_abcdefghijkl_" + "x".repeat(32)));
  execFileSync("sh", ["-n", f]);
});

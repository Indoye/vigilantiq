import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { matchApp } from "./patch/catalog.ts";
import {
  cmpVersion,
  compactNvdItem,
  cvss3Score,
  deviceKey,
  deviceKeyMatches,
  deviceScore,
  enrollToken,
  enrollTokenMatches,
  matchNvd,
  newSalt,
  osvEcosystem,
  osvQueries,
  osvToCves,
  parseDeviceKey,
  parseInventory,
  signJob,
  windowsProduct,
} from "./patch/core.ts";
import { agentScript } from "./patch/scripts.ts";
import { agentReboot, deviceMatches, eligible, inWindow, nextWindowStart, normalizePolicy, pilotVerdict, planItems, PolicyError, type VulnForPlan } from "./patch/policy.ts";

const SECRET = "secret-de-test-0123456789";

test("parc : jetons d'enrôlement et clés d'équipement", () => {
  const salt = newSalt();
  const t = enrollToken(SECRET, 7, salt);
  assert.match(t, /^vqe_7_/);
  assert.ok(enrollTokenMatches(SECRET, t, salt));
  assert.ok(!enrollTokenMatches(SECRET, t, newSalt()), "sel changé : jeton révoqué");
  assert.ok(!enrollTokenMatches("autre-secret-0123456789", t, salt));
  const k = deviceKey(SECRET, 42, salt);
  assert.equal(parseDeviceKey(k)?.id, 42);
  assert.ok(deviceKeyMatches(SECRET, k, salt));
  assert.ok(!deviceKeyMatches(SECRET, k.replace(/.$/, k.endsWith("A") ? "B" : "A"), salt), "signature altérée");
  assert.ok(!deviceKeyMatches(SECRET, t, salt), "un jeton d'enrôlement n'est pas une clé d'équipement");
  assert.equal(signJob(k, 1, "install", '{"a":1}'), signJob(k, 1, "install", '{"a":1}'));
  assert.notEqual(signJob(k, 1, "install", '{"a":1}'), signJob(k, 1, "install", '{"a":2}'));
});

test("parc : inventaire Windows", () => {
  const inv = parseInventory({
    hostname: "PC-COMPTA-01",
    ip: "192.168.1.20",
    domain: "corp.local",
    user: "CORP\\awa",
    rebootPending: true,
    appManager: true,
    os: { family: "windows", name: "Microsoft Windows 10 Pro", build: 19045, ubr: 4412, displayVersion: "22H2", arch: "64 bits", productType: 1 },
    hardware: { manufacturer: "Dell Inc.", model: "Latitude 5420", biosVendor: "Dell Inc.", biosVersion: "1.30.0", serial: "ABC123" },
    kbs: [{ id: "kb5036892", installedOn: "2024-04-10" }, { id: "nope" }],
    apps: [
      { name: "Google Chrome", version: "124.0.6367.60", publisher: "Google LLC" },
      { name: "Google Chrome", version: "124.0.6367.60", publisher: "Google LLC" },
      { name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov" },
    ],
    drivers: [{ name: "Intel(R) Wi-Fi 6 AX201", version: "22.200.0.6", provider: "Intel" }],
  });
  assert.equal(inv.os.version, "10.0.19045.4412");
  assert.equal(inv.os.arch, "x64");
  assert.equal(inv.os.server, false);
  assert.equal(inv.rebootPending, true);
  assert.equal(windowsProduct(inv.os), "windows_10_22h2");
  assert.deepEqual(
    inv.components.map((c) => `${c.kind}:${c.name}`),
    ["os:Microsoft Windows 10 Pro", "kb:KB5036892", "app:Google Chrome", "app:7-Zip 23.01 (x64)", "driver:Intel(R) Wi-Fi 6 AX201", "bios:Dell Inc. Latitude 5420"],
  );
  assert.equal(windowsProduct({ family: "windows", build: 20348, server: true }), "windows_server_2022");
  assert.equal(windowsProduct({ family: "windows", build: 99999, server: false }), null);
});

test("parc : inventaire Linux et requêtes OSV par paquet source", () => {
  const inv = parseInventory({
    hostname: "srv-web",
    os: { family: "linux", name: "Debian GNU/Linux 12 (bookworm)", id: "debian", version: "12", arch: "x86_64", kernel: "6.1.0-18-amd64", pkg: "deb" },
    packages: [
      { name: "libssl3", version: "3.0.11-1~deb12u2", source: "openssl", sourceVersion: "3.0.11-1~deb12u2" },
      { name: "openssl", version: "3.0.11-1~deb12u2", source: "openssl", sourceVersion: "3.0.11-1~deb12u2" },
      { name: "curl", version: "7.88.1-10+deb12u5", source: "curl" },
    ],
  });
  assert.equal(inv.os.server, true);
  const eco = osvEcosystem(inv.os);
  assert.deepEqual(eco, { ecosystem: "Debian:12", approx: false });
  const q = osvQueries(inv.components, eco!.ecosystem, inv.os.pkg);
  assert.deepEqual(
    q.queries.map((x) => `${x.package.name}@${x.version}`),
    ["openssl@3.0.11-1~deb12u2", "curl@7.88.1-10+deb12u5"],
  );
  assert.deepEqual(q.binaries.get("openssl"), ["libssl3", "openssl"]);
  assert.deepEqual(osvEcosystem({ family: "linux", distro: "ubuntu", distroLike: "debian", version: "22.04" }), { ecosystem: "Ubuntu:22.04:LTS", approx: false });
  assert.deepEqual(osvEcosystem({ family: "linux", distro: "ubuntu", distroLike: "debian", version: "23.10" }), { ecosystem: "Ubuntu:23.10", approx: false });
  assert.deepEqual(osvEcosystem({ family: "linux", distro: "rhel", distroLike: "fedora", version: "9.3" }), { ecosystem: "AlmaLinux:9", approx: true });
  assert.equal(osvEcosystem({ family: "linux", distro: "arch", distroLike: "", version: "" }), null);
});

test("parc : avis OSV → CVE, version corrigée et CVSS", () => {
  const dsa = {
    id: "DSA-5764-1",
    aliases: [],
    upstream: ["CVE-2024-5535", "CVE-2024-6119"],
    affected: [
      { package: { name: "openssl", ecosystem: "Debian:12" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.0.14-1~deb12u1" }] }] },
      { package: { name: "openssl", ecosystem: "Debian:11" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.1.1w-0+deb11u2" }] }] },
    ],
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
  };
  const r = osvToCves(dsa, "Debian:12", "openssl");
  assert.deepEqual(r.cves, ["CVE-2024-5535", "CVE-2024-6119"]);
  assert.equal(r.fixed, "3.0.14-1~deb12u1");
  assert.equal(r.cvss, 7.5);
});

test("parc : CVSS 3.x calculé depuis le vecteur", () => {
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"), 5.4);
  assert.equal(cvss3Score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  assert.equal(cvss3Score("CVSS:4.0/AV:N"), null);
});

test("parc : comparaison de versions", () => {
  assert.equal(cmpVersion("1.2.10", "1.2.9"), 1);
  assert.equal(cmpVersion("10.0.19045.4412", "10.0.19045.4529"), -1);
  assert.equal(cmpVersion("124.0.6367.60", "124.0.6367.60"), 0);
  assert.equal(cmpVersion("1.0", "1.0.0"), 0);
  assert.equal(cmpVersion("2.0rc1", "2.0"), -1);
  assert.equal(cmpVersion("23.01", "24.07"), -1);
});

const NVD_WIN = {
  cve: {
    id: "CVE-2024-30051",
    published: "2024-05-14T17:17:13.893",
    metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 7.8 } }] },
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              { vulnerable: true, criteria: "cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*", versionEndExcluding: "10.0.19045.4412" },
              { vulnerable: true, criteria: "cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*", versionEndExcluding: "10.0.19045.4412" },
              { vulnerable: true, criteria: "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*", versionEndExcluding: "10.0.22631.3593" },
            ],
          },
        ],
      },
    ],
  },
};

test("parc : correspondance NVD par plage CPE et architecture", () => {
  const c = compactNvdItem(NVD_WIN, "microsoft", "windows_10_22h2");
  assert.ok(c);
  assert.equal(c.matches.length, 2);
  assert.equal(c.cvss, 7.8);
  assert.deepEqual(matchNvd([c], "10.0.19045.4291", "x64"), [{ cveId: "CVE-2024-30051", cvss: 7.8, fixedVersion: "10.0.19045.4412" }]);
  assert.deepEqual(matchNvd([c], "10.0.19045.4412", "x64"), [], "build corrigé");
  assert.equal(compactNvdItem(NVD_WIN, "google", "chrome"), null);
  const chrome = compactNvdItem(
    {
      cve: {
        id: "CVE-2024-4671",
        published: "2024-05-14",
        metrics: { cvssMetricV31: [{ type: "Secondary", cvssData: { baseScore: 9.6 } }] },
        configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding: "124.0.6367.201" }, { vulnerable: false, criteria: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*" }] }] }],
      },
    },
    "google",
    "chrome",
  );
  assert.ok(chrome);
  assert.equal(matchNvd([chrome], "124.0.6367.60").length, 1);
  assert.equal(matchNvd([chrome], "125.0.6422.60").length, 0);
  assert.equal(compactNvdItem({ cve: { ...NVD_WIN.cve, vulnStatus: "Rejected" } }, "microsoft", "windows_10_22h2"), null);
});

test("parc : catalogue des applications tierces", () => {
  assert.equal(matchApp("Google Chrome")?.winget, "Google.Chrome");
  assert.equal(matchApp("Mozilla Firefox (x64 fr)")?.cpeProduct, "firefox");
  assert.equal(matchApp("Mozilla Firefox ESR (x64 fr)")?.cpeProduct, "firefox_esr");
  assert.equal(matchApp("7-Zip 23.01 (x64)")?.id, "7zip");
  assert.equal(matchApp("Notepad++ (64-bit x64)")?.cpeProduct, "notepad\\+\\+");
  assert.equal(matchApp("FileZilla Server"), null);
  assert.equal(matchApp("Logiciel maison"), null);
});

test("parc : score de priorité sur l'équipement", () => {
  const a = deviceScore({ cvss: 9.8, epss: 0.02, kev: false, ransomware: false, pocs: 0, server: false });
  const b = deviceScore({ cvss: 9.8, epss: 0.02, kev: false, ransomware: false, pocs: 0, server: true });
  assert.equal(b.score, Math.min(100, a.score + 5));
  assert.ok(b.reasons.some((r) => r.startsWith("Serveur")));
  assert.equal(deviceScore({ cvss: 5, epss: null, kev: true, ransomware: false, pocs: 0, server: false }).priority, "urgente");
  assert.ok(deviceScore({ cvss: null, epss: null, kev: false, ransomware: false, pocs: 0, server: false, cvssFromAdvisory: true }).reasons.includes("CVSS non fourni par l’avis de la distribution"));
});

test("parc : politiques, ciblage et fenêtres de maintenance", () => {
  assert.throws(() => normalizePolicy({}), PolicyError);
  assert.throws(() => normalizePolicy({ name: "x", window: { days: [], start: "02:00", end: "05:00", tz: "UTC" } }), PolicyError);
  assert.throws(() => normalizePolicy({ name: "x", window: { days: [1], start: "02:00", end: "05:00", tz: "Mars/Olympus" } }), PolicyError);
  const p = normalizePolicy({ name: "Serveurs critiques", target: { kinds: ["serveur", "imprimante"], groups: ["Dakar"] }, minPriority: "urgente", approval: "auto", window: { days: [6, 7], start: "22:00", end: "04:00", tz: "Africa/Dakar" }, pilotThreshold: 250 });
  assert.deepEqual(p.target.kinds, ["serveur"]);
  assert.equal(p.pilotThreshold, 100);
  const dev = { id: 1, osFamily: "linux", kind: "serveur", groupName: "dakar", tags: [], ring: "production", appManager: false };
  assert.ok(deviceMatches(dev, p.target));
  assert.ok(!deviceMatches({ ...dev, kind: "poste" }, p.target));
  // Le 2 novembre 2026 est un lundi ; Dakar est à UTC+0 toute l'année
  const sat23 = new Date("2026-11-07T23:00:00Z"); // samedi 23 h
  const sun03 = new Date("2026-11-08T03:00:00Z"); // dimanche 3 h (fenêtre du samedi)
  const mon03 = new Date("2026-11-09T03:00:00Z"); // lundi 3 h (fenêtre du dimanche)
  const tue03 = new Date("2026-11-10T03:00:00Z"); // mardi 3 h (fenêtre du lundi : non)
  const fri12 = new Date("2026-11-06T12:00:00Z");
  assert.ok(inWindow(p.window, sat23) && inWindow(p.window, sun03) && inWindow(p.window, mon03));
  assert.ok(!inWindow(p.window, tue03) && !inWindow(p.window, fri12));
  assert.equal(nextWindowStart(p.window, fri12)?.toISOString(), "2026-11-07T22:00:00.000Z");
  // Paris (UTC+1 en novembre) : 02:00 locale = 01:00 UTC
  const paris = normalizePolicy({ name: "p", window: { days: [2], start: "02:00", end: "03:00", tz: "Europe/Paris" } }).window;
  assert.ok(inWindow(paris, new Date("2026-11-10T01:30:00Z")));
  assert.ok(!inWindow(paris, new Date("2026-11-10T02:30:00Z")));
});

test("parc : choix des correctifs, redémarrage et anneau pilote", () => {
  const vulns: VulnForPlan[] = [
    { cveId: "CVE-2024-30051", status: "ouverte", priority: "urgente", kev: true, fix: { kind: "windows", label: "Mise à jour cumulative" } },
    { cveId: "CVE-2024-4671", status: "ouverte", priority: "haute", kev: false, fix: { kind: "app", label: "Google Chrome", winget: "Google.Chrome" } },
    { cveId: "CVE-2024-1111", status: "ignoree", priority: "urgente", kev: false, fix: { kind: "app", label: "7-Zip", winget: "7zip.7zip" } },
    { cveId: "CVE-2024-2222", status: "ouverte", priority: "basse", kev: false, fix: { kind: "app", label: "VLC", winget: "VideoLAN.VLC" } },
  ];
  const win = { osFamily: "windows", appManager: true };
  assert.deepEqual(planItems(win, vulns, { content: "all", minPriority: "haute", kevOnly: false }), {
    items: [{ kind: "windows", categories: ["security", "critical"] }, { kind: "winget", id: "Google.Chrome", name: "Google Chrome" }],
    cves: ["CVE-2024-30051", "CVE-2024-4671"],
  });
  assert.deepEqual(planItems(win, vulns, { content: "apps", minPriority: "basse", kevOnly: false }).items.map((i) => i.kind), ["winget", "winget"]);
  assert.deepEqual(planItems({ ...win, appManager: false }, vulns, { content: "apps", minPriority: "basse", kevOnly: false }).items, []);
  assert.deepEqual(planItems(win, vulns, { content: "all", minPriority: "basse", kevOnly: true }).cves, ["CVE-2024-30051"]);
  assert.deepEqual(planItems(win, vulns, { content: "all", minPriority: "basse", kevOnly: false, cves: ["CVE-2024-4671"] }).cves, ["CVE-2024-4671"]);
  const lin = { osFamily: "linux", appManager: false };
  const pk: VulnForPlan[] = [
    { cveId: "CVE-2024-5535", status: "ouverte", priority: "haute", kev: false, fix: { kind: "package", label: "openssl", package: "openssl", binaries: ["openssl", "libssl3"] } },
    { cveId: "CVE-2024-6119", status: "ouverte", priority: "haute", kev: false, fix: { kind: "package", label: "openssl", package: "openssl", binaries: ["libssl3"] } },
  ];
  assert.deepEqual(planItems(lin, pk, { content: "os", minPriority: "haute", kevOnly: false }).items, [{ kind: "package", name: "openssl", binaries: ["libssl3", "openssl"] }]);
  assert.ok(!eligible(pk[0], { content: "all", minPriority: "haute", kevOnly: false }, win), "paquet Linux sur Windows");

  const w = { days: [6], start: "01:00", end: "04:00", tz: "UTC" };
  assert.equal(agentReboot("immediat", "serveur", null), "aucun", "un serveur ne redémarre jamais hors fenêtre");
  assert.equal(agentReboot("immediat", "serveur", w), "redemarrer");
  assert.equal(agentReboot("fenetre", "poste", null), "prevenir");
  assert.equal(agentReboot("utilisateur", "poste", w), "prevenir");
  assert.equal(agentReboot("immediat", "poste", null), "redemarrer");

  assert.equal(pilotVerdict([{ status: "succes" }, { status: "envoye" }], 100), "en_cours");
  assert.equal(pilotVerdict([{ status: "succes" }, { status: "succes" }], 100), "ok");
  assert.equal(pilotVerdict([{ status: "succes" }, { status: "echec" }], 100), "echec");
  assert.equal(pilotVerdict([{ status: "succes" }, { status: "echec" }], 50), "ok");
  assert.equal(pilotVerdict([{ status: "annule" }], 100), "echec");
});

test("parc : scripts de l'agent (injection) et signatures compatibles avec l'agent Linux", () => {
  const token = enrollToken(SECRET, 3, newSalt());
  const py = agentScript("linux", "https://vigilantiq.example", token);
  assert.ok(py.includes('or "https://vigilantiq.example"') && py.includes(`or "${token}"`));
  assert.ok(agentScript("windows", "https://vigilantiq.example").includes("$Server = 'https://vigilantiq.example'"));
  assert.throws(() => agentScript("linux", "https://x.example'; rm -rf /"));
  assert.throws(() => agentScript("linux", "https://x.example", "vqe_' + evil"));

  // L'agent Python accepte une tâche signée par le serveur et refuse une tâche altérée.
  const dir = mkdtempSync(join(tmpdir(), "vq-agent-"));
  const key = deviceKey(SECRET, 9, newSalt());
  const payload = JSON.stringify({ reason: "test" });
  const good = { id: 5, action: "scan", payload, sig: signJob(key, 5, "scan", payload) };
  const bad = { ...good, payload: JSON.stringify({ reason: "autre" }) };
  const script = `
import importlib.util, json, sys
s = importlib.util.spec_from_file_location("agent", "agent/vigilantiq-agent.py")
a = importlib.util.module_from_spec(s); s.loader.exec_module(a)
print(json.dumps([a.execute(json.loads(sys.argv[1]), sys.argv[3])["status"], a.execute(json.loads(sys.argv[2]), sys.argv[3])["status"]]))`;
  const out = execFileSync("python3", ["-c", script, JSON.stringify(good), JSON.stringify(bad), key], { env: { ...process.env, VQ_STATE_DIR: dir }, encoding: "utf8" });
  assert.deepEqual(JSON.parse(out), ["succes", "echec"]);
});

test("parc : macOS — inventaire Homebrew, correctifs et agent JXA", async () => {
  const inv = parseInventory({
    hostname: "MacBook-Compta",
    os: { family: "macos", name: "macOS 15.1", version: "15.1", macBuild: "24B83", arch: "arm64", desktop: true },
    apps: [{ name: "Firefox", version: "128.0", publisher: "Mozilla Corporation" }],
    brew: [
      { name: "firefox", version: "128.0", kind: "cask" },
      { name: "openssl@3", version: "3.3.1", kind: "formula" },
    ],
    appManager: true,
  });
  assert.equal(inv.os.family, "macos");
  const ff = inv.components.find((c) => c.name === "Firefox");
  assert.deepEqual([ff?.extra.brew, ff?.extra.brewName], ["cask", "firefox"]);
  const ssl = inv.components.find((c) => c.name === "openssl@3");
  assert.deepEqual([ssl?.vendor, ssl?.extra.brew], ["Homebrew", "formula"]);
  assert.equal(inv.components.filter((c) => c.name.toLowerCase() === "firefox").length, 1, "cask rattaché à l'application, pas en double");

  const mac = { osFamily: "macos", appManager: true };
  const vulns: VulnForPlan[] = [
    { cveId: "CVE-2026-30001", status: "ouverte", priority: "haute", kev: false, fix: { kind: "macos", label: "Mise à jour macOS" } },
    { cveId: "CVE-2026-30100", status: "ouverte", priority: "haute", kev: false, fix: { kind: "brew", label: "Firefox", brew: "firefox", cask: true } },
  ];
  assert.deepEqual(planItems(mac, vulns, { content: "all", minPriority: "basse", kevOnly: false }).items, [{ kind: "macos" }, { kind: "brew", name: "firefox", cask: true }]);
  assert.deepEqual(planItems(mac, vulns, { content: "os", minPriority: "basse", kevOnly: false }).items, [{ kind: "macos" }]);
  assert.ok(!eligible(vulns[0], { content: "all", minPriority: "basse", kevOnly: false }, { osFamily: "windows", appManager: true }));

  // Agent JXA chargé avec un minimum d'API osascript simulées : signatures compatibles avec le serveur.
  const { readFileSync } = await import("node:fs");
  const vm = await import("node:vm");
  const nil = { isNil: () => true };
  const ctx = vm.createContext({
    ObjC: { import() {}, unwrap: (x: unknown) => x },
    $: Object.assign(() => ({}), { NSProcessInfo: { processInfo: { environment: { objectForKey: () => nil } } } }),
    Application: { currentApplication: () => ({ doShellScript: () => "" }) },
    console: { log() {} },
  });
  vm.runInContext(readFileSync("agent/vigilantiq-agent.js", "utf8"), ctx);
  const key = deviceKey(SECRET, 9, newSalt());
  const payload = JSON.stringify({ reason: "test" });
  const good = { id: 5, action: "scan", payload, sig: signJob(key, 5, "scan", payload) };
  assert.equal(ctx.execute(good, key).status, "succes");
  assert.equal(ctx.execute({ ...good, payload: JSON.stringify({ reason: "autre" }) }, key).status, "echec");
  const mac2 = agentScript("macos", "https://vigilantiq.example", enrollToken(SECRET, 3, newSalt()));
  assert.ok(mac2.includes('"https://vigilantiq.example"') && !mac2.includes("__VQ_SERVER__"));
});

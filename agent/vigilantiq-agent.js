// VigilantIQ — agent « Parc & correctifs » pour macOS (12 Monterey et suivants, Intel et Apple Silicon).
//
//   sudo osascript -l JavaScript vigilantiq-agent.js install [chemin du script]   installe le service, enrôle le Mac
//   sudo osascript -l JavaScript vigilantiq-agent.js uninstall                    retire le service et la clé
//   sudo osascript -l JavaScript vigilantiq-agent.js once                         une synchronisation (diagnostic)
//   sudo osascript -l JavaScript vigilantiq-agent.js status | inventory           état de l'agent, inventaire
//
// Écrit en JavaScript pour osascript (JXA), présent sur tous les Mac : aucune dépendance à installer.
// Communication sortante uniquement (HTTPS 443), requêtes signées HMAC-SHA256 avec la clé de l'équipement.
// L'agent n'exécute que des actions prédéfinies (inventaire, mises à jour macOS, mises à jour Homebrew,
// redémarrage), et seulement si la tâche est signée avec la clé de l'équipement. Aucun script arbitraire.

ObjC.import("Foundation");

var AGENT_VERSION = "1.0.0";
var SERVER_DEFAULT = "__VQ_SERVER__";
var ENROLL_TOKEN_DEFAULT = "__VQ_ENROLL_TOKEN__";
var BASE_DIR = env("VQ_BASE_DIR") || "/Library/Application Support/VigilantIQ";
var STATE_FILE = BASE_DIR + "/state.json";
var INSTALLED = BASE_DIR + "/agent.js";
var PLIST = env("VQ_PLIST") || "/Library/LaunchDaemons/io.vigilantiq.agent.plist";
var LABEL = "io.vigilantiq.agent";
var LOG_FILE = "/var/log/vigilantiq-agent.log";
// Simulation : les commandes de mise à jour sont journalisées mais pas exécutées (tests, démonstration).
var DRY_RUN = env("VQ_DRY_RUN") === "1";
var REBOOT_MESSAGE = "VigilantIQ : redémarrage dans 5 minutes pour terminer l'installation des correctifs.";

var app = Application.currentApplication();
app.includeStandardAdditions = true;

// ---------- Outils ----------

function env(k) {
  var v = $.NSProcessInfo.processInfo.environment.objectForKey(k);
  return v && !v.isNil() ? ObjC.unwrap(v) : "";
}

function log(msg) {
  console.log("[vigilantiq] " + new Date().toISOString().replace("T", " ").slice(0, 19) + " " + msg);
}

/** Argument shell protégé (apostrophes). */
function q(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

/** Exécute une commande via /bin/sh. Renvoie { code, out } ; ne lève jamais d'exception. */
function sh(cmd) {
  try {
    return { code: 0, out: app.doShellScript(cmd + " 2>&1", { alteringLineEndings: false }) };
  } catch (e) {
    var n = typeof e.errorNumber === "number" ? e.errorNumber : 1;
    return { code: n === 0 ? 1 : n, out: String(e.message || e) };
  }
}

/** Commande de mise à jour : simulée en mode VQ_DRY_RUN. */
function shChange(cmd) {
  if (DRY_RUN) return { code: 0, out: "[simulation] " + cmd };
  return sh(cmd);
}

function readFile(path) {
  var s = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, null);
  return s && !s.isNil() ? ObjC.unwrap(s) : null;
}

function writeFile(path, text, mode) {
  var ok = $(text).writeToFileAtomicallyEncodingError(path, true, $.NSUTF8StringEncoding, null);
  if (!ok) throw new Error("Écriture impossible : " + path);
  sh("chmod " + (mode || "600") + " " + q(path));
}

function exists(path) {
  return $.NSFileManager.defaultManager.fileExistsAtPath(path);
}

function mkdirs(path) {
  sh("mkdir -p " + q(path) + " && chmod 700 " + q(path));
}

function tmpPath(name) {
  return BASE_DIR + "/.tmp-" + name + "-" + Date.now() + "-" + Math.floor(Math.random() * 1e9);
}

// ---------- SHA-256 / HMAC (JavaScript pur : la clé n'apparaît jamais dans la liste des processus) ----------

function utf8(str) {
  var out = [];
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      var d = str.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      }
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return out;
}

var K256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256(bytes) {
  var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  var l = bytes.length;
  var m = bytes.slice();
  m.push(0x80);
  while (m.length % 64 !== 56) m.push(0);
  var bits = l * 8;
  var hi = Math.floor(bits / 0x100000000);
  m.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255, (bits >>> 24) & 255, (bits >>> 16) & 255, (bits >>> 8) & 255, bits & 255);
  var w = new Array(64);
  for (var off = 0; off < m.length; off += 64) {
    for (var i = 0; i < 16; i++) w[i] = (m[off + 4 * i] << 24) | (m[off + 4 * i + 1] << 16) | (m[off + 4 * i + 2] << 8) | m[off + 4 * i + 3];
    for (i = 16; i < 64; i++) {
      var x = w[i - 15], y = w[i - 2];
      var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (i = 0; i < 64; i++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var ch = (e & f) ^ (~e & g);
      var t1 = (k + S1 + ch + K256[i] + w[i]) | 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var mj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + mj) | 0;
      k = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + k) | 0;
  }
  var out = [];
  for (i = 0; i < 8; i++) out.push((h[i] >>> 24) & 255, (h[i] >>> 16) & 255, (h[i] >>> 8) & 255, h[i] & 255);
  return out;
}

function hex(bytes) {
  var s = "";
  for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
  return s;
}

function hmacHex(key, msg) {
  var kb = utf8(key);
  if (kb.length > 64) kb = sha256(kb);
  while (kb.length < 64) kb.push(0);
  var ip = [], op = [];
  for (var i = 0; i < 64; i++) {
    ip.push(kb[i] ^ 0x36);
    op.push(kb[i] ^ 0x5c);
  }
  return hex(sha256(op.concat(sha256(ip.concat(utf8(msg))))));
}

/** Comparaison en temps constant de deux chaînes hexadécimales. */
function sameHex(a, b) {
  a = String(a);
  b = String(b);
  if (a.length !== b.length) return false;
  var r = 0;
  for (var i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---------- État local (clé de l'équipement) ----------

function loadState() {
  var t = readFile(STATE_FILE);
  if (!t) return {};
  try {
    return JSON.parse(t);
  } catch (e) {
    return {};
  }
}

function saveState(state) {
  mkdirs(BASE_DIR);
  writeFile(STATE_FILE, JSON.stringify(state), "600");
}

function serverUrl() {
  var s = (loadState().server || env("VQ_SERVER") || SERVER_DEFAULT).replace(/\/+$/, "");
  var local = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(s);
  if (!/^https:\/\/[A-Za-z0-9.\-:[\]]+$/.test(s) && !local) throw new Error("Adresse du serveur invalide : HTTPS obligatoire (" + s + ")");
  return s;
}

// ---------- HTTP (curl, en-têtes et corps passés par fichiers protégés) ----------

function http(method, path, body, key) {
  mkdirs(BASE_DIR);
  var data = body === undefined || body === null ? "" : JSON.stringify(body);
  var hdr = tmpPath("h"), bodyFile = tmpPath("b"), outFile = tmpPath("o");
  var headers = ["Content-Type: application/json; charset=utf-8", "User-Agent: vigilantiq-agent/" + AGENT_VERSION + " (macos)"];
  if (key) {
    var ts = String(Math.floor(Date.now() / 1000));
    headers.push("Authorization: Bearer " + key, "X-VQ-Timestamp: " + ts, "X-VQ-Signature: sha256=" + hmacHex(key, ts + "." + data));
  }
  try {
    writeFile(hdr, headers.join("\n") + "\n", "600");
    writeFile(bodyFile, data, "600");
    var r = sh(
      "/usr/bin/curl -sS --proto =https,http --max-time 120 -X " + method + " -H @" + q(hdr) + (method === "GET" ? "" : " --data-binary @" + q(bodyFile)) + " -o " + q(outFile) + " -w '%{http_code}' " + q(serverUrl() + path),
    );
    if (r.code !== 0) throw new Error("Connexion impossible : " + r.out.slice(-300));
    var code = parseInt(r.out.trim().slice(-3), 10) || 0;
    var txt = readFile(outFile) || "{}";
    var json;
    try {
      json = JSON.parse(txt || "{}");
    } catch (e) {
      json = { error: "Réponse illisible (HTTP " + code + ")" };
    }
    return { code: code, body: json };
  } finally {
    sh("rm -f " + q(hdr) + " " + q(bodyFile) + " " + q(outFile));
  }
}

// ---------- Inventaire ----------

function trim(s) {
  return String(s || "").trim();
}

function machineId() {
  var r = sh("/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice");
  var m = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(r.out);
  var raw = m ? m[1] : trim(sh("/usr/sbin/scutil --get LocalHostName").out) + trim(sh("/usr/sbin/sysctl -n kern.uuid").out);
  return hex(sha256(utf8("vigilantiq:" + raw))).slice(0, 32);
}

function hostname() {
  var n = trim(sh("/usr/sbin/scutil --get LocalHostName").out);
  return n && !/error|not set/i.test(n) ? n : trim(sh("/bin/hostname -s").out);
}

function localIp() {
  var r = sh("/usr/sbin/ipconfig getifaddr en0 || /usr/sbin/ipconfig getifaddr en1");
  var ip = trim(r.out).split(/\s+/)[0];
  return /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip : null;
}

function consoleUser() {
  var u = trim(sh("/usr/bin/stat -f %Su /dev/console").out);
  return u && u !== "root" && u !== "_mbsetupuser" ? u : "";
}

var MAC_NAMES = { "12": "Monterey", "13": "Ventura", "14": "Sonoma", "15": "Sequoia", "26": "Tahoe" };

function osInfo() {
  var name = trim(sh("/usr/bin/sw_vers -productName").out) || "macOS";
  var version = trim(sh("/usr/bin/sw_vers -productVersion").out);
  var build = trim(sh("/usr/bin/sw_vers -buildVersion").out);
  var extra = trim(sh("/usr/bin/sw_vers -productVersionExtra").out);
  return {
    family: "macos",
    name: name + (MAC_NAMES[version.split(".")[0]] ? " " + MAC_NAMES[version.split(".")[0]] : ""),
    version: version,
    displayVersion: extra && !/usage|unrecognized|error/i.test(extra) ? extra : "",
    macBuild: build,
    arch: trim(sh("/usr/bin/uname -m").out),
    kernel: trim(sh("/usr/bin/uname -r").out),
    desktop: true,
  };
}

/** Éditeur d'après la signature de code (« Developer ID Application: Google LLC (EQHXZ8M8AV) »). */
function publisherOf(app) {
  var s = Array.isArray(app.signed_by) ? app.signed_by[0] : "";
  var m = /^Developer ID Application:\s*(.+?)\s*\([A-Z0-9]+\)$/.exec(s || "");
  if (m) return m[1];
  if (app.obtained_from === "mac_app_store") return "Mac App Store";
  return "";
}

function systemProfile() {
  var r = sh("/usr/sbin/system_profiler -json -detailLevel mini SPApplicationsDataType SPHardwareDataType");
  try {
    return JSON.parse(r.out.slice(r.out.indexOf("{")));
  } catch (e) {
    log("system_profiler illisible : " + r.out.slice(0, 200));
    return {};
  }
}

function applications(sp) {
  var out = [];
  var list = sp.SPApplicationsDataType || [];
  for (var i = 0; i < list.length; i++) {
    var a = list[i];
    var path = String(a.path || "");
    // Applications installées par l'utilisateur ou l'administrateur ; les apps système suivent macOS
    if (a.obtained_from === "apple") continue;
    if (!/^\/Applications\/|^\/Users\/[^/]+\/Applications\//.test(path)) continue;
    if (/\.app\/.+\.app$/.test(path)) continue;
    if (!a.version) continue;
    out.push({ name: String(a._name || "").slice(0, 160), version: String(a.version).slice(0, 60), publisher: publisherOf(a).slice(0, 120), arch: a.arch_kind === "arch_arm" ? "arm64" : a.arch_kind === "arch_i64" ? "x64" : "" });
  }
  return out;
}

function hardware(sp) {
  var h = (sp.SPHardwareDataType || [])[0] || {};
  var ram = String(h.physical_memory || "");
  var gb = /([\d.]+)\s*GB/i.exec(ram);
  return {
    manufacturer: "Apple",
    model: String(h.machine_name || "") + (h.machine_model ? " (" + h.machine_model + ")" : ""),
    serial: String(h.serial_number || ""),
    cpu: String(h.chip_type || h.cpu_type || ""),
    ramMb: gb ? String(Math.round(parseFloat(gb[1]) * 1024)) : "",
    biosVendor: "Apple",
    biosVersion: String(h.boot_rom_version || ""),
  };
}

/** Homebrew : propriétaire de l'installation (brew refuse de tourner en root). */
function brewInfo() {
  var paths = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"];
  for (var i = 0; i < paths.length; i++) {
    if (!exists(paths[i])) continue;
    var owner = trim(sh("/usr/bin/stat -f %Su " + q(paths[i])).out);
    if (owner && owner !== "root") return { bin: paths[i], owner: owner };
  }
  return null;
}

function brewCmd(b, args) {
  return "/usr/bin/sudo -u " + q(b.owner) + " -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_INSTALL_CLEANUP=1 " + q(b.bin) + " " + args;
}

function brewList(b) {
  var out = [];
  if (!b) return out;
  var kinds = [["formula", "list --formula --versions"], ["cask", "list --cask --versions"]];
  for (var i = 0; i < kinds.length; i++) {
    var r = sh(brewCmd(b, kinds[i][1]));
    if (r.code !== 0) continue;
    var lines = r.out.split("\n");
    for (var j = 0; j < lines.length; j++) {
      var f = trim(lines[j]).split(/\s+/);
      if (f.length < 2 || !/^[A-Za-z0-9@._+-]+$/.test(f[0])) continue;
      out.push({ name: f[0], version: f[f.length - 1], kind: kinds[i][0] });
    }
  }
  return out.slice(0, 1500);
}

/** Mises à jour proposées par Apple (sans nouvelle recherche réseau). */
function pendingUpdates() {
  var r = sh("/usr/sbin/softwareupdate --list --no-scan");
  var out = [];
  var re = /\* Label: (.+)\n\s*(Title: [^\n]*)/g;
  var m;
  while ((m = re.exec(r.out + "\n"))) {
    var line = m[2];
    var f = function (k) {
      var x = new RegExp(k + ": ([^,]*)").exec(line);
      return x ? trim(x[1]) : "";
    };
    out.push({ label: trim(m[1]), title: f("Title"), version: f("Version"), recommended: f("Recommended") !== "NO", restart: /restart/i.test(f("Action")) });
  }
  return out.slice(0, 50);
}

function inventory() {
  var sp = systemProfile();
  var b = brewInfo();
  var st = loadState();
  return {
    hostname: hostname(),
    ip: localIp(),
    domain: "",
    user: consoleUser(),
    rebootPending: Boolean(st.rebootRequired),
    appManager: Boolean(b),
    os: osInfo(),
    hardware: hardware(sp),
    apps: applications(sp),
    brew: brewList(b),
    pendingUpdates: pendingUpdates(),
  };
}

// ---------- Actions ----------

function notifyUser(text) {
  var u = consoleUser();
  if (!u) return;
  var uid = trim(sh("/usr/bin/id -u " + q(u)).out);
  if (!/^\d+$/.test(uid)) return;
  sh("/bin/launchctl asuser " + uid + " /usr/bin/sudo -u " + q(u) + " /usr/bin/osascript -e " + q("display notification " + JSON.stringify(text) + ' with title "VigilantIQ"'));
}

function doReboot(mode, lines) {
  var st = loadState();
  if (mode === "redemarrer" && st.rebootRequired) {
    notifyUser(REBOOT_MESSAGE);
    var r = shChange("/sbin/shutdown -r +5");
    lines.push(r.code === 0 ? "Redémarrage programmé dans 5 minutes" : "Redémarrage impossible : " + r.out.slice(-300));
    if (r.code === 0) {
      st.rebootRequired = false;
      saveState(st);
    }
    return r.code === 0;
  }
  if (mode === "prevenir" && st.rebootRequired) {
    notifyUser("Des correctifs ont été installés. Redémarrez votre Mac dès que possible.");
    lines.push("Utilisateur prévenu : redémarrage nécessaire");
  }
  return false;
}

function brewVersions(b, names) {
  var vers = {};
  if (!b || !names.length) return vers;
  var r = sh(brewCmd(b, "list --versions " + names.map(q).join(" ")));
  var lines = r.out.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var f = trim(lines[i]).split(/\s+/);
    if (f.length >= 2) vers[f[0]] = f[f.length - 1];
  }
  return vers;
}

function jobInstall(payload) {
  var items = Array.isArray(payload.items) ? payload.items : [];
  var lines = [];
  var data = {};
  var failed = false;
  var st = loadState();

  // Mises à jour Apple (macOS et applications Apple)
  if (items.some(function (it) { return it.kind === "macos"; })) {
    var r = shChange("/usr/sbin/softwareupdate --install --recommended --agree-to-license");
    lines.push("softwareupdate :\n" + r.out.slice(-6000));
    if (r.code !== 0 || /requires? (an )?(administrator|admin|authorization|authentication)|not authorized|Failed to/i.test(r.out)) {
      failed = true;
      lines.push(
        "Les mises à jour macOS n’ont pas pu être installées sans intervention : sur les Mac Apple Silicon, Apple exige l’accord d’un utilisateur (Réglages Système → Mise à jour de logiciels) ou une gestion MDM.",
      );
      notifyUser("Des mises à jour de sécurité macOS sont disponibles : ouvrez Réglages Système → Mise à jour de logiciels.");
    } else if (/restart|redémarr/i.test(r.out)) {
      st.rebootRequired = true;
      saveState(st);
    }
  }

  // Homebrew (formules et casks), exécuté avec le compte propriétaire de Homebrew
  var brewItems = items.filter(function (it) { return it.kind === "brew" && /^[A-Za-z0-9@._+-]+$/.test(String(it.name || "")); });
  if (brewItems.length) {
    var b = brewInfo();
    if (!b) {
      failed = true;
      lines.push("Homebrew introuvable sur ce Mac.");
    } else {
      var names = brewItems.map(function (it) { return it.name; });
      var before = brewVersions(b, names);
      data.before = before;
      var u = sh(brewCmd(b, "update --quiet"));
      if (u.code !== 0) lines.push("brew update : " + u.out.slice(-500));
      var formulas = brewItems.filter(function (it) { return !it.cask; }).map(function (it) { return q(it.name); });
      var casks = brewItems.filter(function (it) { return it.cask; }).map(function (it) { return q(it.name); });
      if (formulas.length) {
        var rf = shChange(brewCmd(b, "upgrade --formula " + formulas.join(" ")));
        lines.push("brew upgrade --formula :\n" + rf.out.slice(-4000));
        if (rf.code !== 0) failed = true;
      }
      if (casks.length) {
        var rc = shChange(brewCmd(b, "upgrade --cask " + casks.join(" ")));
        lines.push("brew upgrade --cask :\n" + rc.out.slice(-4000));
        if (rc.code !== 0) failed = true;
      }
      var after = brewVersions(b, names);
      data.after = after;
      var changed = names.filter(function (n) { return after[n] && after[n] !== before[n]; });
      lines.push("Mis à jour : " + (changed.map(function (n) { return n + " " + (before[n] || "?") + " → " + after[n]; }).join(", ") || "aucun changement (déjà à jour ?)"));
    }
  }
  if (!items.length) return ["echec", "Aucune mise à jour à installer sur ce Mac.", {}];
  data.rebootRequired = Boolean(loadState().rebootRequired);
  if (!failed) data.rebooting = doReboot(payload.reboot || "aucun", lines);
  return [failed ? "echec" : "succes", lines.join("\n"), data];
}

function jobReboot(payload) {
  if (!payload.force && !loadState().rebootRequired) return ["succes", "Aucun redémarrage nécessaire.", { rebooting: false }];
  notifyUser(REBOOT_MESSAGE);
  var r = shChange("/sbin/shutdown -r +5");
  return [r.code === 0 ? "succes" : "echec", r.out.slice(-500) || "Redémarrage programmé dans 5 minutes", { rebooting: r.code === 0 }];
}

function execute(job, key) {
  var payloadJson = typeof job.payload === "string" ? job.payload : "{}";
  var want = hmacHex(key, job.id + "." + job.action + "." + payloadJson);
  if (!sameHex(want, job.sig || "")) return { id: job.id, status: "echec", log: "Signature de la tâche invalide : tâche refusée." };
  var res;
  try {
    var payload = JSON.parse(payloadJson);
    if (job.action === "scan") res = ["succes", "Inventaire envoyé.", { inventory: true }];
    else if (job.action === "install") res = jobInstall(payload);
    else if (job.action === "rollback") res = ["echec", "Retour arrière non pris en charge sur macOS : réinstallez la version précédente depuis l’éditeur si nécessaire.", {}];
    else if (job.action === "reboot") res = jobReboot(payload);
    else res = ["echec", "Action inconnue : refusée.", {}];
  } catch (e) {
    res = ["echec", "Erreur de l'agent : " + e, {}];
  }
  return { id: job.id, status: res[0], log: String(res[1]).slice(-20000), data: res[2] };
}

// ---------- Synchronisation ----------

function enroll(state) {
  var token = env("VQ_ENROLL_TOKEN") || ENROLL_TOKEN_DEFAULT;
  if (token.indexOf("vqe_") !== 0) throw new Error("Jeton d'enrôlement absent : téléchargez l'installeur depuis la console VigilantIQ.");
  var r = http("POST", "/api/v1/agent/enroll", { token: token, machineId: machineId(), hostname: hostname(), os: osInfo(), agentVersion: AGENT_VERSION });
  if (r.code !== 200 || !r.body.key) throw new Error("Enrôlement refusé : " + (r.body.error || r.code));
  state.deviceId = r.body.deviceId;
  state.key = r.body.key;
  state.server = serverUrl();
  state.lastInventory = 0;
  saveState(state);
  log("Mac enrôlé (n° " + r.body.deviceId + ")");
  return state;
}

function selfUpdate(state, upd) {
  var script = String(upd.script || "");
  if (!script || !sameHex(hmacHex(state.key, "script." + script), upd.sig || "")) {
    log("Mise à jour de l'agent refusée : signature invalide");
    return false;
  }
  writeFile(INSTALLED, script, "700");
  log("Agent mis à jour en version " + upd.version);
  return true;
}

function sync(state, results, forceInventory) {
  var body = { agentVersion: AGENT_VERSION, rebootPending: Boolean(state.rebootRequired), results: results };
  var due = Date.now() / 1000 - (state.lastInventory || 0) > (state.inventoryHours || 4) * 3600;
  if (forceInventory || due || state.wantInventory) body.inventory = inventory();
  var r = http("POST", "/api/v1/agent/sync", body, state.key);
  if (r.code === 401) throw new Error("Clé refusée par le serveur (" + (r.body.error || "401") + ") : équipement supprimé ou clé renouvelée. Réinstallez l'agent.");
  if (r.code !== 200) throw new Error(r.body.error || "HTTP " + r.code);
  var fresh = loadState();
  if (body.inventory) fresh.lastInventory = Date.now() / 1000;
  fresh.wantInventory = Boolean(r.body.wantInventory);
  fresh.inventoryHours = r.body.inventoryHours || 4;
  saveState(fresh);
  for (var k in fresh) state[k] = fresh[k];
  return r.body;
}

/** Une synchronisation, puis les tâches reçues et leur compte rendu immédiat. */
function cycle(state) {
  var r = sync(state, [], false);
  if (r.update) selfUpdate(state, r.update);
  var jobs = r.jobs || [];
  var rounds = 0;
  while (jobs.length && rounds++ < 10) {
    var results = [];
    var inv = false;
    for (var i = 0; i < jobs.length; i++) {
      log("Tâche " + jobs[i].id + " : " + jobs[i].action);
      results.push(execute(jobs[i], state.key));
      inv = inv || jobs[i].action === "scan" || jobs[i].action === "install";
    }
    r = sync(state, results, inv);
    jobs = r.jobs || [];
  }
}

// ---------- Installation ----------

function isRoot() {
  return trim(sh("/usr/bin/id -u").out) === "0";
}

function install(src) {
  if (!isRoot()) throw new Error("Lancez l'installation en administrateur : sudo osascript -l JavaScript vigilantiq-agent.js install");
  var code = readFile(src);
  if (!code) throw new Error("Script de l'agent introuvable : " + src + " (indiquez son chemin après « install »).");
  mkdirs(BASE_DIR);
  writeFile(INSTALLED, code, "700");
  var state = loadState();
  if (!state.key) enroll(state);
  var plist =
    '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n' +
    "<key>Label</key><string>" + LABEL + "</string>\n" +
    "<key>ProgramArguments</key><array><string>/usr/bin/osascript</string><string>-l</string><string>JavaScript</string><string>" + INSTALLED + "</string><string>once</string></array>\n" +
    "<key>StartInterval</key><integer>60</integer>\n<key>RunAtLoad</key><true/>\n<key>LowPriorityIO</key><true/>\n" +
    "<key>StandardOutPath</key><string>" + LOG_FILE + "</string>\n<key>StandardErrorPath</key><string>" + LOG_FILE + "</string>\n</dict></plist>\n";
  writeFile(PLIST, plist, "644");
  sh("/usr/sbin/chown root:wheel " + q(PLIST));
  sh("/bin/launchctl bootout system " + q(PLIST));
  var r = sh("/bin/launchctl bootstrap system " + q(PLIST));
  return r.code === 0 ? "Service " + LABEL + " installé et démarré. Le Mac apparaît dans la console VigilantIQ (Parc & correctifs)." : "Service installé, démarrage impossible : " + r.out;
}

function uninstall() {
  if (!isRoot()) throw new Error("Lancez la désinstallation en administrateur (sudo).");
  sh("/bin/launchctl bootout system " + q(PLIST));
  sh("rm -f " + q(PLIST) + " " + q(STATE_FILE) + " " + q(INSTALLED));
  return "Agent désinstallé. Supprimez l'équipement dans la console pour effacer ses données.";
}

function run(argv) {
  var cmd = argv[0] || "once";
  try {
    if (cmd === "install") return install(argv[1] || "/tmp/vigilantiq-agent.js");
    if (cmd === "uninstall") return uninstall();
    if (cmd === "status") {
      var s = loadState();
      return JSON.stringify({ version: AGENT_VERSION, enrolled: Boolean(s.key), deviceId: s.deviceId || null, server: s.server || SERVER_DEFAULT, lastInventory: s.lastInventory || null }, null, 2);
    }
    if (cmd === "inventory") return JSON.stringify(inventory(), null, 2).slice(0, 20000);
    if (cmd === "once") {
      var state = loadState();
      if (!state.key) state = enroll(state);
      cycle(state);
      return "";
    }
    return "Commandes : install [chemin], uninstall, once, status, inventory";
  } catch (e) {
    log(String(e.message || e));
    if (cmd !== "once") throw e;
    return "";
  }
}

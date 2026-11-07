/**
 * Threat Hunting — logique pure (sans base) : lecture des données de l'agent collecteur et des événements
 * SIEM/EDR, index des IOC, règles de détection (IOC, exfiltration, tunnel DNS, Tor, domaines ressemblants),
 * clés des agents et chiffrement des identifiants des connecteurs.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Ioc } from "../cti/sources.ts";
import { isLookalike } from "../cti/leaks.ts";

export type ObsKind = "ip" | "domain" | "url" | "sha256" | "sha1" | "md5";
export interface Obs {
  kind: ObsKind;
  value: string;
  context: Record<string, string | number>;
}
export interface HostInfo {
  name: string;
  os: string;
  ip: string | null;
}

export const LIMITS = { bodyBytes: 3_000_000, lines: 30_000, obsPerBatch: 8_000 };

// ---------- Normalisation ----------

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]{2,39}$/i;
const HEX = { sha256: /^[a-f0-9]{64}$/, sha1: /^[a-f0-9]{40}$/, md5: /^[a-f0-9]{32}$/ };
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
/** Extensions de fichiers qui ressemblent à des domaines dans des journaux (« svchost.exe ») */
const FILE_TLD = new Set("exe dll sys log txt tmp dat ini cfg conf json xml yml yaml csv bat cmd ps1 vbs msi lnk zip rar gz tar jar class py sh js ts md html htm php asp aspx jsp png jpg jpeg gif pdf doc docx xls xlsx ppt pptx bak old db sqlite local lan internal home corp arpa".split(" "));

export function isPublicIp(ip: string): boolean {
  if (IPV4.test(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
    return true;
  }
  if (ip.includes(":") && IPV6.test(ip)) {
    const l = ip.toLowerCase();
    return !(l === "::1" || l === "::" || l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("::ffff:127."));
  }
  return false;
}

export function normIp(raw: string): string | null {
  let ip = raw.trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (ip.startsWith("::ffff:") && IPV4.test(ip.slice(7))) ip = ip.slice(7);
  ip = ip.replace(/%.*$/, "");
  return IPV4.test(ip) || (ip.includes(":") && IPV6.test(ip)) ? ip : null;
}

export function normDomain(raw: string): string | null {
  const d = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!DOMAIN.test(d)) return null;
  const tld = d.slice(d.lastIndexOf(".") + 1);
  return FILE_TLD.has(tld) ? null : d;
}

export function hostOfUrl(u: string): string | null {
  try {
    return normDomain(new URL(u).hostname) ?? normIp(new URL(u).hostname);
  } catch {
    return null;
  }
}

function hashKind(h: string): ObsKind | null {
  const v = h.toLowerCase();
  return HEX.sha256.test(v) ? "sha256" : HEX.sha1.test(v) ? "sha1" : HEX.md5.test(v) ? "md5" : null;
}

const clip = (s: unknown, n = 160) => String(s ?? "").replace(/[\u0000-\u001f]/g, " ").trim().slice(0, n);

/** Ajoute un observable (dédoublonné par type et valeur ; garde le contexte le plus riche et cumule les octets). */
class Bag {
  map = new Map<string, Obs>();
  add(kind: ObsKind, value: string | null, context: Record<string, string | number> = {}) {
    if (!value || this.map.size >= LIMITS.obsPerBatch) return;
    if (kind === "ip" && !isPublicIp(value)) return;
    const k = `${kind}|${value}`;
    const prev = this.map.get(k);
    if (!prev) this.map.set(k, { kind, value, context });
    else {
      const bytes = Number(prev.context.bytesOut ?? 0) + Number(context.bytesOut ?? 0);
      prev.context = { ...prev.context, ...context, ...(bytes ? { bytesOut: bytes } : {}) };
      prev.context.hits = Number(prev.context.hits ?? 1) + 1;
    }
  }
  list() {
    return [...this.map.values()];
  }
}

// ---------- Agent collecteur (protocole texte, une ligne par élément) ----------

/**
 * host  <nom> <système>
 * conn  <ip distante> <port distant> <processus>
 * dns   <nom de domaine>
 * proc  <nom> <chemin> <sha256>
 * Champs séparés par des tabulations ; les lignes inconnues sont ignorées.
 */
export function parseAgentPayload(text: string): { host: HostInfo; obs: Obs[]; counts: Record<string, number> } {
  const host: HostInfo = { name: "", os: "", ip: null };
  const bag = new Bag();
  const counts: Record<string, number> = { conn: 0, dns: 0, proc: 0 };
  const lines = text.split(/\r?\n/).slice(0, LIMITS.lines);
  for (const line of lines) {
    const f = line.split("\t");
    const t = f[0]?.trim().toLowerCase();
    if (t === "host") {
      host.name = clip(f[1], 80);
      host.os = clip(f[2], 120);
      host.ip = f[3] ? normIp(f[3]) : null;
    } else if (t === "conn") {
      const ip = normIp(f[1] ?? "");
      if (!ip) continue;
      counts.conn++;
      const ctx: Record<string, string | number> = { port: Number(f[2]) || 0, process: clip(f[3], 80) };
      if (f[4] && Number(f[4]) > 0) ctx.bytesOut = Number(f[4]);
      bag.add("ip", ip, ctx);
    } else if (t === "dns") {
      const d = normDomain(f[1] ?? "");
      if (!d) continue;
      counts.dns++;
      bag.add("domain", d, {});
    } else if (t === "proc") {
      const k = hashKind((f[3] ?? "").trim());
      if (!k) continue;
      counts.proc++;
      bag.add(k, f[3].trim().toLowerCase(), { process: clip(f[1], 80), path: clip(f[2], 260) });
    }
  }
  return { host, obs: bag.list(), counts };
}

// ---------- Événements SIEM/EDR (Elastic, OpenSearch, Wazuh, Splunk, Cortex XDR) ----------

const HOST_FIELDS = ["host_name", "agent_hostname", "agent_fqdn", "host.name", "host.hostname", "agent.name", "agent.hostname", "computer_name", "data.win.system.computer", "host", "hostname", "dvc", "dest_host"];
const IP_FIELDS = ["action_remote_ip", "dst_action_external_ip", "destination.ip", "destination.address", "data.dstip", "dst_ip", "dest_ip", "dest", "remote_ip", "data.win.eventdata.destinationIp", "server.ip", "source.ip", "data.srcip", "src_ip", "src", "client.ip"];
const DOMAIN_FIELDS = ["dns_query_name", "action_external_hostname", "dst_action_external_hostname", "fw_url_domain", "dns.question.name", "data.win.eventdata.queryName", "query", "destination.domain", "url.domain", "data.url", "dest_host", "server.domain"];
const URL_FIELDS = ["malicious_urls", "url.full", "url.original", "data.url", "url", "http.url"];
const HASH_FIELDS = ["action_file_sha256", "action_file_md5", "actor_process_image_sha256", "actor_process_image_md5", "causality_actor_process_image_sha256", "action_process_image_sha256", "os_actor_process_image_sha256", "action_file_macro_sha256", "file.hash.sha256", "process.hash.sha256", "file.hash.sha1", "process.hash.sha1", "file.hash.md5", "process.hash.md5", "data.win.eventdata.hashes", "syscheck.sha256_after", "syscheck.sha1_after", "syscheck.md5_after", "hash", "sha256", "file_hash"];
const BYTES_FIELDS = ["destination.bytes", "network.bytes", "source.bytes", "bytes_out", "sent_bytes", "bytes"];
const PROC_FIELDS = ["actor_process_image_name", "causality_actor_process_image_name", "action_process_image_name", "process.name", "process.executable", "data.win.eventdata.image", "process", "app"];

function pick(o: Record<string, unknown>, path: string): unknown {
  if (path in o) return o[path];
  let cur: unknown = o;
  for (const p of path.split(".")) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}
const first = (o: Record<string, unknown>, paths: string[]) => {
  for (const p of paths) {
    const v = pick(o, p);
    if (v !== undefined && v !== null && v !== "") return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
};

/** Un événement SIEM/EDR → nom d'hôte et observables (champs ECS, Wazuh et Splunk usuels). */
export function extractEvent(ev: Record<string, unknown>): { host: string | null; obs: Obs[] } {
  const bag = new Bag();
  const proc = clip(first(ev, PROC_FIELDS), 80);
  const bytes = Number(first(ev, BYTES_FIELDS)) || 0;
  for (const p of IP_FIELDS) {
    const v = pick(ev, p);
    for (const x of Array.isArray(v) ? v : [v]) {
      const ip = typeof x === "string" ? normIp(x) : null;
      if (ip) bag.add("ip", ip, { ...(proc ? { process: proc } : {}), ...(bytes && p.startsWith("dest") ? { bytesOut: bytes } : {}) });
    }
  }
  for (const p of DOMAIN_FIELDS) {
    const v = pick(ev, p);
    if (typeof v === "string") bag.add("domain", normDomain(v.replace(/^https?:\/\//, "").split(/[/:]/)[0]), proc ? { process: proc } : {});
  }
  for (const p of URL_FIELDS) {
    const raw = pick(ev, p);
    // Cortex XDR : « malicious_urls » peut être une liste ou une chaîne séparée par des virgules
    const vals = Array.isArray(raw) ? raw : typeof raw === "string" ? raw.split(/[,\s]+(?=https?:\/\/)/i) : [];
    for (const v of vals) {
      if (typeof v === "string" && /^https?:\/\//i.test(v) && v.length < 800) {
        bag.add("url", v.trim(), proc ? { process: proc } : {});
        const h = hostOfUrl(v);
        if (h) bag.add(IPV4.test(h) ? "ip" : "domain", h, proc ? { process: proc } : {});
      }
    }
  }
  for (const p of HASH_FIELDS) {
    const v = pick(ev, p);
    if (typeof v !== "string") continue;
    // Sysmon : « SHA256=…,MD5=… »
    for (const part of v.split(/[,;\s]+/)) {
      const h = part.replace(/^[A-Z0-9]+=/i, "").toLowerCase();
      const k = hashKind(h);
      if (k) bag.add(k, h, proc ? { process: proc } : {});
    }
  }
  const hv = first(ev, HOST_FIELDS);
  const host = typeof hv === "string" ? clip(hv, 80) : hv && typeof hv === "object" && "name" in (hv as object) ? clip((hv as { name: unknown }).name, 80) : null;
  return { host: host || null, obs: bag.list() };
}

// ---------- Index des IOC ----------

export interface IocHit {
  value: string;
  type: string;
  threat: string;
  malware: string;
  source: string;
  confidence: number | null;
  ref: string;
  /** Correspondance indirecte (hôte d'une URL d'hameçonnage) */
  weak?: boolean;
  port?: number;
}

export interface IocIndex {
  ip: Map<string, IocHit>;
  domain: Map<string, IocHit>;
  urlHost: Map<string, IocHit>;
  url: Map<string, IocHit>;
  hash: Map<string, IocHit>;
  size: number;
}

export function buildIndex(iocs: Ioc[]): IocIndex {
  const idx: IocIndex = { ip: new Map(), domain: new Map(), urlHost: new Map(), url: new Map(), hash: new Map(), size: 0 };
  for (const i of iocs) {
    const base = { value: i.value, type: i.type, threat: i.threat, malware: i.malware, source: i.source, confidence: i.confidence, ref: i.ref };
    if (i.type === "ip" || i.type === "ip:port") {
      const [ip, port] = i.type === "ip:port" ? [i.value.slice(0, i.value.lastIndexOf(":")), Number(i.value.slice(i.value.lastIndexOf(":") + 1))] : [i.value, undefined];
      const n = normIp(ip);
      if (n) idx.ip.set(n, { ...base, port });
    } else if (i.type === "domain") {
      const d = normDomain(i.value);
      if (d) idx.domain.set(d, base);
    } else if (i.type === "url") {
      idx.url.set(i.value.trim(), base);
      const h = hostOfUrl(i.value);
      if (h && !idx.urlHost.has(h)) idx.urlHost.set(h, { ...base, weak: true });
    } else if (i.type === "md5" || i.type === "sha1" || i.type === "sha256") {
      idx.hash.set(i.value.toLowerCase(), base);
    }
  }
  idx.size = idx.ip.size + idx.domain.size + idx.url.size + idx.hash.size;
  return idx;
}

/** Domaine ou un de ses parents présent dans la liste (sous.domaine.malveillant.com → malveillant.com). */
function domainLookup(map: Map<string, IocHit>, d: string): IocHit | undefined {
  const parts = d.split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const hit = map.get(parts.slice(i).join("."));
    if (hit) return hit;
  }
  return undefined;
}

// ---------- Règles de détection ----------

export type Severity = "critique" | "haute" | "moyenne" | "info";
export interface FindingDraft {
  kind: "ioc" | "exfiltration" | "tunnel_dns" | "tor" | "ressemblant";
  indicatorType: string;
  indicator: string;
  source: string;
  threat: string;
  malware: string;
  severity: Severity;
  confidence: number | null;
  evidence: Record<string, unknown>;
}

export function iocSeverity(h: IocHit): Severity {
  const t = `${h.threat} ${h.type}`.toLowerCase();
  if (h.weak) return "moyenne";
  if (/c2|commande|botnet|cc_|command/.test(t)) return "critique";
  if (/payload|malware|distribution|ransom|stealer/.test(t)) return "critique";
  if (/phish|hameçonnage/.test(t)) return "haute";
  return "haute";
}

/** Services de partage, de dépôt et de tunnel souvent utilisés pour exfiltrer des données. */
export const EXFIL_SERVICES: Record<string, string> = {
  "pastebin.com": "Site de dépôt (Pastebin)",
  "paste.ee": "Site de dépôt",
  "hastebin.com": "Site de dépôt",
  "ghostbin.com": "Site de dépôt",
  "rentry.co": "Site de dépôt",
  "transfer.sh": "Transfert de fichiers anonyme",
  "file.io": "Transfert de fichiers éphémère",
  "gofile.io": "Hébergement de fichiers anonyme",
  "anonfiles.com": "Hébergement de fichiers anonyme",
  "bayfiles.com": "Hébergement de fichiers anonyme",
  "catbox.moe": "Hébergement de fichiers anonyme",
  "0x0.st": "Hébergement de fichiers anonyme",
  "temp.sh": "Transfert de fichiers éphémère",
  "sendspace.com": "Transfert de fichiers",
  "mega.nz": "Stockage chiffré (MEGA)",
  "mega.co.nz": "Stockage chiffré (MEGA)",
  "ngrok.io": "Tunnel vers Internet (ngrok)",
  "ngrok-free.app": "Tunnel vers Internet (ngrok)",
  "trycloudflare.com": "Tunnel vers Internet (Cloudflare Quick Tunnel)",
  "serveo.net": "Tunnel vers Internet",
  "localtunnel.me": "Tunnel vers Internet",
  "api.telegram.org": "API de bot Telegram (canal d’exfiltration fréquent)",
  "discord.com": "Webhooks Discord (canal d’exfiltration fréquent)",
  "discordapp.com": "Webhooks Discord (canal d’exfiltration fréquent)",
  "webhook.site": "Collecteur de requêtes",
  "requestbin.net": "Collecteur de requêtes",
  "interactsh.com": "Collecteur de requêtes (tests d’intrusion)",
  "oast.fun": "Collecteur de requêtes (tests d’intrusion)",
  "duckdns.org": "DNS dynamique",
  "no-ip.com": "DNS dynamique",
  "ddns.net": "DNS dynamique",
};
const TOR_PORTS = new Set([9001, 9030, 9050, 9051, 9150]);
const BIG_UPLOAD = 200 * 1024 * 1024;

const entropy = (s: string) => {
  const m = new Map<string, number>();
  for (const c of s) m.set(c, (m.get(c) ?? 0) + 1);
  let e = 0;
  for (const n of m.values()) e -= (n / s.length) * Math.log2(n / s.length);
  return e;
};
const parentOf = (d: string) => d.split(".").slice(-2).join(".");

export interface HuntExtras {
  /** Domaines surveillés (et vérifiés) de l'utilisateur, pour les domaines ressemblants */
  ownDomains: string[];
  /** IOC supplémentaires issus des fuites du darkweb (domaines en clair) */
  leakDomains?: Map<string, { title: string; source: string }>;
}

/** Observables d'un équipement → détections. */
export function hunt(obs: Obs[], idx: IocIndex, extras: HuntExtras): FindingDraft[] {
  const out = new Map<string, FindingDraft>();
  const put = (f: FindingDraft) => {
    const k = `${f.kind}|${f.indicator}`;
    const prev = out.get(k);
    const rank = { critique: 3, haute: 2, moyenne: 1, info: 0 };
    if (!prev || rank[f.severity] > rank[prev.severity]) out.set(k, f);
  };
  const subsByParent = new Map<string, string[]>();

  for (const o of obs) {
    const ctx = o.context;
    // 1. Correspondance avec les IOC
    let hit: IocHit | undefined;
    if (o.kind === "ip") hit = idx.ip.get(o.value);
    else if (o.kind === "domain") hit = domainLookup(idx.domain, o.value) ?? idx.urlHost.get(o.value);
    else if (o.kind === "url") hit = idx.url.get(o.value) ?? (hostOfUrl(o.value) ? domainLookup(idx.domain, hostOfUrl(o.value)!) : undefined);
    else hit = idx.hash.get(o.value);
    if (hit) {
      const portMismatch = hit.port && ctx.port && Number(ctx.port) !== hit.port;
      put({
        kind: "ioc",
        indicatorType: o.kind,
        indicator: o.value,
        source: hit.source,
        threat: hit.threat,
        malware: hit.malware,
        severity: portMismatch ? "haute" : iocSeverity(hit),
        confidence: hit.confidence,
        evidence: { ...ctx, ioc: hit.value, ref: hit.ref, ...(hit.weak ? { note: "Hôte d’une URL d’hameçonnage connue" } : {}), ...(portMismatch ? { note: `Port ${ctx.port} (IOC sur le port ${hit.port})` } : {}) },
      });
    }
    if (o.kind === "domain" && extras.leakDomains) {
      const lk = extras.leakDomains.get(o.value);
      if (lk) put({ kind: "ioc", indicatorType: "domain", indicator: o.value, source: lk.source, threat: `Cité dans une fuite : ${lk.title}`, malware: "", severity: "haute", confidence: null, evidence: { ...ctx } });
    }
    // 2. Exfiltration : services de partage, de dépôt, de tunnel ; gros envois
    const dom = o.kind === "domain" ? o.value : o.kind === "url" ? hostOfUrl(o.value) : null;
    if (dom) {
      const svc = Object.keys(EXFIL_SERVICES).find((s) => dom === s || dom.endsWith(`.${s}`));
      const discordHook = svc?.startsWith("discord") && o.kind === "url" && /\/api\/webhooks\//.test(o.value);
      if (svc && (!svc.startsWith("discord") || discordHook)) {
        put({ kind: "exfiltration", indicatorType: o.kind, indicator: dom, source: "Règle VigilantIQ", threat: EXFIL_SERVICES[svc], malware: "", severity: svc.includes("telegram") || svc.includes("ngrok") || svc.includes("trycloudflare") ? "haute" : "moyenne", confidence: null, evidence: { ...ctx } });
      }
      // 3. Domaine ressemblant à un domaine de l'utilisateur (hameçonnage ciblé)
      const own = extras.ownDomains.find((w) => isLookalike(dom, w));
      if (own) put({ kind: "ressemblant", indicatorType: "domain", indicator: dom, source: "Règle VigilantIQ", threat: `Ressemble à ${own}`, malware: "", severity: "haute", confidence: null, evidence: { ...ctx, ressemble: own } });
      // 4. Tunnel DNS : sous-domaines longs et aléatoires sous un même domaine
      const label = dom.split(".")[0];
      if (label.length >= 30 && entropy(label) > 3.6) subsByParent.set(parentOf(dom), [...(subsByParent.get(parentOf(dom)) ?? []), label]);
    }
    if (o.kind === "ip") {
      if (TOR_PORTS.has(Number(ctx.port)) || /^tor(\.exe)?$/i.test(String(ctx.process ?? ""))) {
        put({ kind: "tor", indicatorType: "ip", indicator: o.value, source: "Règle VigilantIQ", threat: "Connexion au réseau Tor", malware: "", severity: "haute", confidence: null, evidence: { ...ctx } });
      }
      if (Number(ctx.bytesOut ?? 0) >= BIG_UPLOAD) {
        put({ kind: "exfiltration", indicatorType: "ip", indicator: o.value, source: "Règle VigilantIQ", threat: `Envoi volumineux vers l’extérieur (${Math.round(Number(ctx.bytesOut) / 1048576)} Mo)`, malware: "", severity: "moyenne", confidence: null, evidence: { ...ctx } });
      }
    }
  }
  for (const [parent, labels] of subsByParent) {
    if (labels.length >= 8)
      put({ kind: "tunnel_dns", indicatorType: "domain", indicator: parent, source: "Règle VigilantIQ", threat: `Tunnel DNS probable : ${labels.length} sous-domaines aléatoires`, malware: "", severity: "haute", confidence: null, evidence: { exemples: labels.slice(0, 3) } });
  }
  return [...out.values()];
}

// ---------- Clés des agents ----------

const sig = (secret: string, id: number, salt: string) => createHmac("sha256", secret).update(`hunt-asset:${id}:${salt}`).digest("base64url").slice(0, 32);
export const newSalt = () => randomBytes(9).toString("base64url");
export const agentKey = (secret: string, id: number, salt: string) => `vqa_${id}_${salt}_${sig(secret, id, salt)}`;
export function parseAgentKey(k: string): { id: number; salt: string; sig: string } | null {
  const m = /^vqa_(\d{1,9})_([A-Za-z0-9_-]{12})_([A-Za-z0-9_-]{32})$/.exec(k);
  return m ? { id: Number(m[1]), salt: m[2], sig: m[3] } : null;
}
export function agentKeyMatches(secret: string, k: string, salt: string | null): boolean {
  const p = parseAgentKey(k);
  if (!p || !salt || p.salt !== salt) return false;
  const want = sig(secret, p.id, salt);
  return want.length === p.sig.length && timingSafeEqual(Buffer.from(want), Buffer.from(p.sig));
}

// ---------- Chiffrement des identifiants des connecteurs (AES-256-GCM) ----------

const keyOf = (secret: string) => createHash("sha256").update(`vigilantiq:siem:${secret}`).digest();
export function seal(secret: string, plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", keyOf(secret), iv);
  const enc = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return `v1.${iv.toString("base64url")}.${c.getAuthTag().toString("base64url")}.${enc.toString("base64url")}`;
}
export function unseal(secret: string, sealed: string): string {
  const [v, iv, tag, data] = sealed.split(".");
  if (v !== "v1") throw new Error("Format chiffré inconnu");
  const d = createDecipheriv("aes-256-gcm", keyOf(secret), Buffer.from(iv, "base64url"));
  d.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([d.update(Buffer.from(data, "base64url")), d.final()]).toString("utf8");
}

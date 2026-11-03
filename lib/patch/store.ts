/**
 * Parc & correctifs — base de données : enrôlement et synchronisation des agents, inventaire, corrélation avec les
 * CVE, politiques, déploiements (anneau pilote, production, retour arrière), tâches, audit et passe quotidienne.
 */
import { and, asc, desc, eq, inArray, lt, ne, notInArray, sql } from "drizzle-orm";
import { dbConfigured, getDb } from "@/db";
import { patchAudit, patchCache, patchComponent, patchDeployment, patchDevice, patchEnroll, patchJob, patchPolicy, patchVuln } from "@/db/schema";
import { verifySignature } from "../cti/leaks.ts";
import { serverSecret } from "../cti/leakstore.ts";
import { matchApp } from "./catalog.ts";
import {
  AGENT_VERSION,
  cmpVersion,
  deviceKey,
  deviceKeyMatches,
  deviceScore,
  enrollToken,
  enrollTokenMatches,
  LIMITS,
  matchNvd,
  newSalt,
  osvEcosystem,
  osvQueries,
  osvToCves,
  parseDeviceKey,
  parseEnrollToken,
  parseInventory,
  signJob,
  signScript,
  windowsProduct,
  type OsInfo,
} from "./core.ts";
import { agentReboot, deviceMatches, inWindow, nextWindowStart, normalizePolicy, normalizeWindow, pilotVerdict, planItems, PolicyError, type Fix, type JobItem, type Selection, type Window } from "./policy.ts";
import { agentScript, type AgentOs } from "./scripts.ts";
import { nvdProduct, osvQueryBatch, osvVulns, signals } from "./sources.ts";

export class PatchError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

export const POLL_SECONDS = 60;
export const INVENTORY_HOURS = 4;
/** Un équipement est « en ligne » s'il s'est synchronisé dans les 5 dernières minutes. */
export const ONLINE_MS = 5 * 60_000;
const JOB_TIMEOUT_MS = 6 * 3600_000;
const MAX_DEVICES = () => Number(process.env.PATCH_MAX_DEVICES || 1000);
const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));
const ACTIVE = ["attente_approbation", "planifie", "pilote", "production"];
type Device = typeof patchDevice.$inferSelect;
type Job = typeof patchJob.$inferSelect;
type Deployment = typeof patchDeployment.$inferSelect;

async function audit(orgId: string, actor: string, action: string, target = "", detail: Record<string, unknown> = {}) {
  await getDb().insert(patchAudit).values({ orgId, actor, action, target, detail });
}

// ---------- Enrôlement ----------

export async function getEnrollment(orgId: string): Promise<{ token: string; createdAt: string } | null> {
  const [r] = await getDb().select().from(patchEnroll).where(eq(patchEnroll.orgId, orgId));
  return r ? { token: enrollToken(serverSecret(), r.id, r.keySalt), createdAt: r.createdAt.toISOString() } : null;
}

/** Crée ou renouvelle le jeton d'enrôlement : l'ancien cesse de fonctionner (les équipements déjà enrôlés gardent leur clé). */
export async function rotateEnrollment(orgId: string, actor: string): Promise<string> {
  const salt = newSalt();
  const [r] = await getDb()
    .insert(patchEnroll)
    .values({ orgId, keySalt: salt })
    .onConflictDoUpdate({ target: patchEnroll.orgId, set: { keySalt: salt, createdAt: new Date() } })
    .returning();
  await audit(orgId, actor, "jeton_renouvele");
  return enrollToken(serverSecret(), r.id, r.keySalt);
}

export async function revokeEnrollment(orgId: string, actor: string): Promise<void> {
  await getDb().delete(patchEnroll).where(eq(patchEnroll.orgId, orgId));
  await audit(orgId, actor, "jeton_revoque");
}

/** Propriétaire d'un jeton d'enrôlement valide, ou null. */
export async function enrollmentOwner(token: string): Promise<string | null> {
  const p = parseEnrollToken(token);
  if (!p) return null;
  const [r] = await getDb().select().from(patchEnroll).where(eq(patchEnroll.id, p.id));
  return r && enrollTokenMatches(serverSecret(), token, r.keySalt) ? r.orgId : null;
}

// ---------- Agent ----------

/** Enrôlement d'une machine : création (ou réinstallation) de l'équipement et remise de sa clé. */
export async function enrollDevice(body: Record<string, unknown>): Promise<{ deviceId: number; key: string }> {
  const orgId = await enrollmentOwner(String(body.token ?? ""));
  if (!orgId) throw new PatchError("Jeton d’enrôlement invalide ou renouvelé : téléchargez un nouvel installeur depuis la console.", 401);
  const machineId = String(body.machineId ?? "");
  if (!/^[a-f0-9]{16,64}$/i.test(machineId)) throw new PatchError("Identifiant de machine invalide.");
  const os = (body.os && typeof body.os === "object" ? body.os : {}) as Record<string, unknown>;
  const osFamily = os.family === "windows" ? "windows" : os.family === "linux" ? "linux" : null;
  if (!osFamily) throw new PatchError("Système non pris en charge (Windows ou Linux).");
  const hostname = String(body.hostname ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, 80) || "machine";
  const db = getDb();
  const salt = newSalt();
  const [existing] = await db.select().from(patchDevice).where(and(eq(patchDevice.orgId, orgId), eq(patchDevice.machineId, machineId)));
  let id: number;
  if (existing) {
    await db.update(patchDevice).set({ keySalt: salt, osFamily, hostname, inventoryRequested: true }).where(eq(patchDevice.id, existing.id));
    id = existing.id;
  } else {
    const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(patchDevice).where(eq(patchDevice.orgId, orgId));
    if (n >= MAX_DEVICES()) throw new PatchError(`Limite de ${MAX_DEVICES()} équipements atteinte.`, 403);
    const [row] = await db
      .insert(patchDevice)
      .values({ orgId, machineId, name: hostname, hostname, osFamily, osName: String(os.name ?? "").slice(0, 120), kind: osFamily === "linux" ? "serveur" : Number(os.productType) > 1 ? "serveur" : "poste", keySalt: salt })
      .returning({ id: patchDevice.id });
    id = row.id;
  }
  await audit(orgId, `agent:${hostname}`, existing ? "agent_reinstalle" : "agent_enrole", hostname, { deviceId: id, os: osFamily, version: String(body.agentVersion ?? "") });
  return { deviceId: id, key: deviceKey(serverSecret(), id, salt) };
}

/** Authentifie une synchronisation : clé de l'équipement (Bearer), signature HMAC du corps, fenêtre de 5 minutes. */
export async function authenticateDevice(headers: Headers, body: string): Promise<Device> {
  const auth = headers.get("authorization") ?? "";
  const key = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const p = parseDeviceKey(key);
  if (!p) throw new PatchError("Clé d’équipement absente ou mal formée.", 401);
  const [d] = await getDb().select().from(patchDevice).where(eq(patchDevice.id, p.id));
  if (!d || !deviceKeyMatches(serverSecret(), key, d.keySalt)) throw new PatchError("Clé d’équipement invalide ou révoquée.", 401);
  const bad = verifySignature(key, headers.get("x-vq-timestamp"), body, headers.get("x-vq-signature"));
  if (bad) throw new PatchError(bad, 401);
  return d;
}

const isNewer = (a: string, b: string) => cmpVersion(a, b) > 0;

/** Synchronisation d'un agent : comptes rendus, inventaire, tâches à exécuter, mise à jour de l'agent. */
export async function agentSync(d: Device, key: string, raw: Record<string, unknown>, origin: string) {
  const db = getDb();
  const now = new Date();
  const agentVersion = String(raw.agentVersion ?? "").slice(0, 20);
  await db.update(patchDevice).set({ lastSeenAt: now, agentVersion, rebootPending: raw.rebootPending === true }).where(eq(patchDevice.id, d.id));

  // 1. Comptes rendus des tâches
  const results = Array.isArray(raw.results) ? raw.results.slice(0, 50) : [];
  for (const r of results) await recordResult(d, r as Record<string, unknown>);

  // 2. Inventaire
  let correlate = false;
  if (raw.inventory && typeof raw.inventory === "object") {
    await saveInventory(d, raw.inventory);
    correlate = true;
  }

  // 3. Avancement des déploiements, puis tâches à envoyer
  await advanceDeployments(d.orgId);
  const jobs = await dispatch(d.id, key, now);
  const [fresh] = await db.select({ want: patchDevice.inventoryRequested }).from(patchDevice).where(eq(patchDevice.id, d.id));
  const os: AgentOs = d.osFamily === "windows" ? "windows" : "linux";
  let update: { version: string; script: string; sig: string } | undefined;
  if (agentVersion && isNewer(AGENT_VERSION, agentVersion)) {
    try {
      const script = agentScript(os, origin);
      update = { version: AGENT_VERSION, script, sig: signScript(key, script) };
    } catch (e) {
      console.error(`[parc] mise à jour de l’agent impossible : ${msg(e)}`);
    }
  }
  return { response: { pollSeconds: POLL_SECONDS, inventoryHours: INVENTORY_HOURS, wantInventory: Boolean(fresh?.want), jobs, ...(update ? { update } : {}) }, correlate };
}

async function saveInventory(d: Device, raw: unknown) {
  const inv = parseInventory(raw);
  const db = getDb();
  await db.transaction(async (tx) => {
    await tx.delete(patchComponent).where(eq(patchComponent.deviceId, d.id));
    for (let i = 0; i < inv.components.length; i += 1000) {
      await tx.insert(patchComponent).values(inv.components.slice(i, i + 1000).map((c) => ({ deviceId: d.id, kind: c.kind, name: c.name, vendor: c.vendor, version: c.version, source: c.source, extra: c.extra })));
    }
    await tx
      .update(patchDevice)
      .set({
        hostname: inv.hostname || d.hostname,
        osFamily: inv.os.family,
        osName: inv.os.name,
        osVersion: inv.os.version,
        arch: inv.os.arch,
        ip: inv.ip,
        domain: inv.domain,
        loggedUser: inv.loggedUser,
        kind: inv.os.server ? "serveur" : "poste",
        hardware: { ...inv.hardware, ...(inv.os.distro ? { distro: inv.os.distro } : {}), ...(inv.os.distroLike ? { distroLike: inv.os.distroLike } : {}), ...(inv.os.pkg ? { pkg: inv.os.pkg } : {}), ...(inv.os.kernel ? { kernel: inv.os.kernel } : {}), ...(inv.os.build ? { build: String(inv.os.build) } : {}), ...(inv.os.displayVersion ? { displayVersion: inv.os.displayVersion } : {}) },
        appManager: inv.appManager,
        rebootPending: inv.rebootPending,
        lastInventoryAt: new Date(),
        inventoryRequested: false,
      })
      .where(eq(patchDevice.id, d.id));
  });
}

/** OsInfo reconstitué depuis la fiche de l'équipement (pour la corrélation). */
function osOf(d: Device): OsInfo {
  const h = d.hardware ?? {};
  const build = Number(h.build ?? d.osVersion.split(".")[2]);
  const ubr = Number(d.osVersion.split(".")[3]);
  return {
    family: d.osFamily === "windows" ? "windows" : "linux",
    name: d.osName,
    version: d.osVersion,
    build: Number.isInteger(build) && build > 0 ? build : null,
    ubr: Number.isInteger(ubr) ? ubr : null,
    displayVersion: h.displayVersion ?? "",
    arch: d.arch,
    server: d.kind === "serveur",
    distro: h.distro ?? "",
    distroLike: h.distroLike ?? "",
    kernel: h.kernel ?? "",
    pkg: h.pkg ?? "",
  };
}

async function recordResult(d: Device, r: Record<string, unknown>) {
  const id = Number(r.id);
  if (!Number.isInteger(id)) return;
  const status = r.status === "succes" ? "succes" : "echec";
  const db = getDb();
  const [job] = await db
    .update(patchJob)
    .set({ status, log: String(r.log ?? "").slice(-LIMITS.logChars), result: r.data && typeof r.data === "object" ? (r.data as Record<string, unknown>) : null, finishedAt: new Date() })
    .where(and(eq(patchJob.id, id), eq(patchJob.deviceId, d.id), inArray(patchJob.status, ["envoye", "en_attente"])))
    .returning();
  if (!job) return;
  await audit(d.orgId, `agent:${d.name}`, `tache_${status}`, d.name, { jobId: job.id, action: job.action, deploymentId: job.deploymentId });
  if (job.action === "install" && status === "echec") await createRollback(job, d, "auto");
  if (job.action === "install" && status === "succes" && job.result?.rebootRequired === true && job.payload.reboot === "prevenir" && d.kind === "poste" && job.deploymentId) {
    const [dep] = await db.select().from(patchDeployment).where(eq(patchDeployment.id, job.deploymentId));
    const at = new Date(Date.now() + (dep?.rebootDeferHours ?? 24) * 3600_000);
    await db.insert(patchJob).values({ orgId: d.orgId, deviceId: d.id, deploymentId: job.deploymentId, action: "reboot", phase: job.phase, payload: { reason: "Redémarrage différé après installation des correctifs" }, notBefore: at });
  }
}

/** Retour arrière d'une installation : mises à jour Windows et applications, ou versions précédentes des paquets. */
async function createRollback(job: Job, d: Device, why: "auto" | "manuel"): Promise<boolean> {
  const data = job.result ?? {};
  const payload: Record<string, unknown> = { sourceJob: job.id, reboot: job.payload.reboot ?? "aucun" };
  if (d.osFamily === "windows") {
    const kbs = Array.isArray(data.kbs) ? data.kbs.filter((k) => /^KB\d{6,8}$/.test(String(k))) : [];
    const apps = Array.isArray(data.apps) ? (data.apps as Record<string, unknown>[]).filter((a) => a && a.from) : [];
    if (!kbs.length && !apps.length) return false;
    Object.assign(payload, { kbs, apps });
  } else {
    if (data.transaction) payload.transaction = String(data.transaction);
    else if (data.before && typeof data.before === "object" && Object.keys(data.before).length) payload.before = data.before;
    else return false;
  }
  const db = getDb();
  const [dup] = await db
    .select({ id: patchJob.id })
    .from(patchJob)
    .where(and(eq(patchJob.deviceId, d.id), eq(patchJob.action, "rollback"), sql`${patchJob.payload}->>'sourceJob' = ${String(job.id)}`));
  if (dup) return false;
  await db.insert(patchJob).values({ orgId: d.orgId, deviceId: d.id, deploymentId: job.deploymentId, action: "rollback", phase: job.phase, payload });
  await audit(d.orgId, why === "auto" ? "système" : "utilisateur", "retour_arriere", d.name, { jobId: job.id, motif: why === "auto" ? "échec de l’installation" : "demande manuelle" });
  return true;
}

/** Tâches prêtes pour l'équipement : hors fenêtre de maintenance ou au-delà du parallélisme maximal, elles attendent. */
async function dispatch(deviceId: number, key: string, now: Date) {
  const db = getDb();
  const rows = await db
    .select({ j: patchJob, dep: patchDeployment })
    .from(patchJob)
    .leftJoin(patchDeployment, eq(patchDeployment.id, patchJob.deploymentId))
    .where(and(eq(patchJob.deviceId, deviceId), eq(patchJob.status, "en_attente")))
    .orderBy(asc(patchJob.id))
    .limit(10);
  const out: { id: number; action: string; payload: string; sig: string }[] = [];
  for (const { j, dep } of rows) {
    if (j.notBefore && j.notBefore > now) continue;
    if (dep) {
      if (!["pilote", "production"].includes(dep.status) && j.action === "install") continue;
      if (dep.status === "annule") continue;
      if (j.action !== "rollback" && !inWindow(dep.window as Window | null, now)) continue;
      const [{ n }] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(patchJob)
        .where(and(eq(patchJob.deploymentId, dep.id), eq(patchJob.status, "envoye")));
      if (n >= dep.maxParallel) continue;
    }
    const [claimed] = await db
      .update(patchJob)
      .set({ status: "envoye", sentAt: now, attempts: sql`${patchJob.attempts} + 1` })
      .where(and(eq(patchJob.id, j.id), eq(patchJob.status, "en_attente")))
      .returning();
    if (!claimed) continue;
    const payload = JSON.stringify(claimed.payload);
    out.push({ id: claimed.id, action: claimed.action, payload, sig: signJob(key, claimed.id, claimed.action, payload) });
  }
  return out;
}

// ---------- Corrélation avec les CVE ----------

interface Hit {
  cveId: string;
  componentKind: string;
  componentName: string;
  componentVersion: string;
  source: "NVD" | "OSV";
  advisory: string;
  cvss: number | null;
  fix: Fix;
}

/** Firmware (BIOS) : produit NVD « <modèle>_firmware » pour les constructeurs dont la NVD suit cette forme. */
function firmwareProduct(hw: Record<string, string>): { vendor: string; product: string } | null {
  const maker = (hw.manufacturer ?? "").toLowerCase();
  const vendor = maker.startsWith("dell") ? "dell" : /^(hp|hewlett)/.test(maker) ? "hp" : null;
  const model = (hw.model ?? "")
    .toLowerCase()
    .replace(/^(hp|dell)\s+/, "")
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_|_$/g, "");
  return vendor && model ? { vendor, product: `${model}_firmware` } : null;
}

/** Croise l'inventaire d'un équipement avec la NVD et OSV, puis enregistre ses CVE (ouvertes, corrigées). */
export async function correlateDevice(deviceId: number): Promise<{ vulns: number; errors: string[] }> {
  const db = getDb();
  const [d] = await db.select().from(patchDevice).where(eq(patchDevice.id, deviceId));
  if (!d) throw new PatchError("Équipement introuvable.", 404);
  const comps = await db.select().from(patchComponent).where(eq(patchComponent.deviceId, d.id));
  const os = osOf(d);
  const hits: Hit[] = [];
  const errors: string[] = [];
  /** Sources interrogées avec succès : seules leurs CVE absentes sont déclarées corrigées. */
  const okSources = new Set<string>();
  let nvdTried = false;
  let nvdOk = true;

  // Windows : la mise à jour cumulative ferme les CVE du système
  const product = windowsProduct(os);
  if (product) {
    nvdTried = true;
    try {
      const { items, stale } = await nvdProduct("o", "microsoft", product);
      if (stale) errors.push("NVD indisponible : données du cache précédent");
      for (const h of matchNvd(items, os.version, os.arch))
        hits.push({ cveId: h.cveId, componentKind: "os", componentName: d.osName || "Windows", componentVersion: os.version, source: "NVD", advisory: "", cvss: h.cvss, fix: { kind: "windows", label: "Mise à jour cumulative Windows", fixedVersion: h.fixedVersion } });
    } catch (e) {
      nvdOk = false;
      errors.push(`NVD (${product}) : ${msg(e)}`);
    }
  } else if (os.family === "windows" && os.build) errors.push(`Version de Windows non suivie (build ${os.build})`);

  // Applications tierces du catalogue
  const apps = new Map<string, { entry: NonNullable<ReturnType<typeof matchApp>>; name: string; version: string }[]>();
  for (const c of comps) {
    if (c.kind !== "app" || !c.version) continue;
    const entry = matchApp(c.name);
    if (entry) apps.set(entry.id, [...(apps.get(entry.id) ?? []), { entry, name: c.name, version: c.version }]);
  }
  for (const list of apps.values()) {
    const { entry } = list[0];
    nvdTried = true;
    try {
      const { items } = await nvdProduct("a", entry.cpeVendor, entry.cpeProduct);
      for (const a of list)
        for (const h of matchNvd(items, a.version))
          hits.push({
            cveId: h.cveId,
            componentKind: "app",
            componentName: a.name,
            componentVersion: a.version,
            source: "NVD",
            advisory: "",
            cvss: h.cvss,
            fix: entry.winget ? { kind: "app", label: entry.label, winget: entry.winget, fixedVersion: h.fixedVersion } : { kind: "none", label: `${entry.label} : mise à jour manuelle`, fixedVersion: h.fixedVersion },
          });
    } catch (e) {
      nvdOk = false;
      errors.push(`NVD (${entry.label}) : ${msg(e)}`);
    }
  }

  // Firmware (alerte : mise à jour manuelle)
  const fw = firmwareProduct(d.hardware ?? {});
  const bios = comps.find((c) => c.kind === "bios");
  if (fw && bios?.version) {
    nvdTried = true;
    try {
      const { items } = await nvdProduct("o", fw.vendor, fw.product);
      for (const h of matchNvd(items, bios.version))
        hits.push({ cveId: h.cveId, componentKind: "bios", componentName: bios.name, componentVersion: bios.version, source: "NVD", advisory: "", cvss: h.cvss, fix: { kind: "none", label: "Mise à jour du BIOS chez le constructeur", fixedVersion: h.fixedVersion } });
    } catch (e) {
      // Produit absent de la NVD : rien à signaler
      if (!/404/.test(msg(e))) errors.push(`NVD (firmware) : ${msg(e)}`);
    }
  }
  if (nvdTried && nvdOk) okSources.add("NVD");
  if (!nvdTried) okSources.add("NVD");

  // Linux : avis des distributions via OSV
  const eco = osvEcosystem(os);
  if (os.family === "linux") {
    if (!eco) errors.push(`Distribution non prise en charge (${os.distro || "inconnue"} ${os.version})`);
    else {
      try {
        const { queries, binaries, versions } = osvQueries(
          comps.map((c) => ({ kind: c.kind as "package", name: c.name, vendor: c.vendor, version: c.version, source: c.source, extra: c.extra })),
          eco.ecosystem,
          os.pkg,
        );
        const ids = await osvQueryBatch(queries);
        const details = await osvVulns(ids.flat());
        queries.forEach((q, i) => {
          for (const vid of ids[i]) {
            const v = details.get(vid);
            if (!v) continue;
            const r = osvToCves(v, eco.ecosystem, q.package.name);
            for (const cve of r.cves)
              hits.push({
                cveId: cve,
                componentKind: "package",
                componentName: q.package.name,
                componentVersion: versions.get(q.package.name) ?? q.version,
                source: "OSV",
                advisory: vid,
                cvss: r.cvss,
                fix: r.fixed ? { kind: "package", label: q.package.name, package: q.package.name, binaries: binaries.get(q.package.name) ?? [q.package.name], fixedVersion: r.fixed } : { kind: "none", label: "Pas encore de correctif dans la distribution" },
              });
          }
        });
        okSources.add("OSV");
        if (eco.approx) errors.push(`Avis ${eco.ecosystem} utilisés pour ${os.distro} ${os.version} (mêmes paquets) : correspondance approchée`);
      } catch (e) {
        errors.push(`OSV : ${msg(e)}`);
      }
    }
  }

  // Dédoublonnage (même CVE, même composant) : on garde le plus grave et un correctif automatique si possible
  const uniq = new Map<string, Hit>();
  for (const h of hits) {
    const k = `${h.cveId}|${h.componentName}`;
    const prev = uniq.get(k);
    if (!prev) uniq.set(k, h);
    else {
      prev.cvss = Math.max(prev.cvss ?? 0, h.cvss ?? 0) || prev.cvss || h.cvss;
      if (prev.fix.kind === "none" && h.fix.kind !== "none") prev.fix = h.fix;
      if (!prev.advisory && h.advisory) prev.advisory = h.advisory;
    }
  }
  const list = [...uniq.values()];
  const sig = await signals(list.map((h) => h.cveId));
  errors.push(...sig.errors);

  const now = new Date();
  for (let i = 0; i < list.length; i += 500) {
    const rows = list.slice(i, i + 500).map((h) => {
      const kev = sig.kev.get(h.cveId);
      const s = deviceScore({ cvss: h.cvss, epss: sig.epss.get(h.cveId) ?? null, kev: Boolean(kev), ransomware: Boolean(kev?.ransomware), pocs: sig.pocs.get(h.cveId) ?? 0, server: d.kind === "serveur", cvssFromAdvisory: h.source === "OSV" });
      return {
        orgId: d.orgId,
        deviceId: d.id,
        cveId: h.cveId,
        componentKind: h.componentKind,
        componentName: h.componentName.slice(0, 200),
        componentVersion: h.componentVersion.slice(0, 80),
        source: h.source,
        advisory: h.advisory,
        cvss: h.cvss,
        epss: sig.epss.get(h.cveId) ?? null,
        kev: Boolean(kev),
        ransomware: Boolean(kev?.ransomware),
        score: s.score,
        priority: s.priority,
        reasons: s.reasons,
        fix: h.fix as unknown as Record<string, unknown>,
        firstSeen: now,
        lastSeen: now,
      };
    });
    await db
      .insert(patchVuln)
      .values(rows)
      .onConflictDoUpdate({
        target: [patchVuln.deviceId, patchVuln.cveId, patchVuln.componentName],
        set: {
          componentVersion: sql`excluded.component_version`,
          cvss: sql`excluded.cvss`,
          epss: sql`excluded.epss`,
          kev: sql`excluded.kev`,
          ransomware: sql`excluded.ransomware`,
          score: sql`excluded.score`,
          priority: sql`excluded.priority`,
          reasons: sql`excluded.reasons`,
          fix: sql`excluded.fix`,
          advisory: sql`excluded.advisory`,
          lastSeen: now,
          status: sql`case when ${patchVuln.status} = 'corrigee' then 'ouverte' else ${patchVuln.status} end`,
          fixedAt: sql`case when ${patchVuln.status} = 'corrigee' then null else ${patchVuln.fixedAt} end`,
        },
      });
  }
  // CVE ouvertes qui ont disparu de l'inventaire : corrigées (constaté sur le poste)
  if (okSources.size) {
    const seen = list.map((h) => `${h.cveId}|${h.componentName.slice(0, 200)}`);
    await db
      .update(patchVuln)
      .set({ status: "corrigee", fixedAt: now })
      .where(
        and(
          eq(patchVuln.deviceId, d.id),
          eq(patchVuln.status, "ouverte"),
          inArray(patchVuln.source, [...okSources]),
          seen.length ? notInArray(sql`${patchVuln.cveId} || '|' || ${patchVuln.componentName}`, seen) : undefined,
        ),
      );
  }
  await db
    .update(patchDevice)
    .set({ correlatedAt: now, correlateError: errors.length ? errors.join(" · ").slice(0, 600) : null })
    .where(eq(patchDevice.id, d.id));
  return { vulns: list.length, errors };
}

// ---------- Politiques ----------

export async function listPolicies(orgId: string) {
  const rows = await getDb().select().from(patchPolicy).where(eq(patchPolicy.orgId, orgId)).orderBy(asc(patchPolicy.name));
  return rows.map((p) => ({ ...p, createdAt: p.createdAt.toISOString(), updatedAt: p.updatedAt.toISOString() }));
}

export async function savePolicy(orgId: string, actor: string, id: number | null, raw: unknown) {
  let p;
  try {
    p = normalizePolicy(raw);
  } catch (e) {
    throw new PatchError(e instanceof PolicyError ? e.message : "Politique invalide.");
  }
  const db = getDb();
  const values = { ...p, target: p.target as unknown as Record<string, string[]>, window: p.window as unknown as Record<string, unknown> | null, updatedAt: new Date() };
  if (id) {
    const r = await db.update(patchPolicy).set(values).where(and(eq(patchPolicy.orgId, orgId), eq(patchPolicy.id, id))).returning({ id: patchPolicy.id });
    if (!r.length) throw new PatchError("Politique introuvable.", 404);
  } else {
    const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(patchPolicy).where(eq(patchPolicy.orgId, orgId));
    if (n >= 50) throw new PatchError("50 politiques au plus.");
    const [r] = await db.insert(patchPolicy).values({ orgId, ...values }).returning({ id: patchPolicy.id });
    id = r.id;
  }
  await audit(orgId, actor, "politique_enregistree", p.name, { id, approval: p.approval, minPriority: p.minPriority });
  return id;
}

export async function deletePolicy(orgId: string, actor: string, id: number) {
  const r = await getDb().delete(patchPolicy).where(and(eq(patchPolicy.orgId, orgId), eq(patchPolicy.id, id))).returning({ name: patchPolicy.name });
  if (r.length) await audit(orgId, actor, "politique_supprimee", r[0].name);
}

/**
 * Applique les politiques actives : pour chaque politique, les équipements visés qui ont des CVE à corriger et pas
 * déjà une installation en cours reçoivent un déploiement (lancé, ou en attente d'approbation).
 */
export async function runPolicies(orgId: string): Promise<number> {
  const db = getDb();
  const policies = await db.select().from(patchPolicy).where(and(eq(patchPolicy.orgId, orgId), eq(patchPolicy.enabled, true)));
  if (!policies.length) return 0;
  const devices = await db.select().from(patchDevice).where(eq(patchDevice.orgId, orgId));
  const vulns = await db.select().from(patchVuln).where(and(eq(patchVuln.orgId, orgId), eq(patchVuln.status, "ouverte")));
  const busy = new Set(
    (
      await db
        .select({ d: patchJob.deviceId })
        .from(patchJob)
        .where(and(eq(patchJob.orgId, orgId), inArray(patchJob.action, ["install", "rollback"]), inArray(patchJob.status, ["en_attente", "envoye"])))
    ).map((r) => r.d),
  );
  let created = 0;
  for (const p of policies) {
    const pending = await db
      .select()
      .from(patchDeployment)
      .where(and(eq(patchDeployment.policyId, p.id), inArray(patchDeployment.status, ACTIVE)));
    const inFlight = new Set(pending.flatMap((x) => x.deviceIds));
    const sel: Selection = { content: p.content as Selection["content"], minPriority: p.minPriority as Selection["minPriority"], kevOnly: p.kevOnly };
    const target = p.target as { groups: string[]; tags: string[]; os: string[]; kinds: string[] };
    const ids = devices
      .filter((d) => !busy.has(d.id) && !inFlight.has(d.id))
      .filter((d) => deviceMatches({ ...d, tags: d.tags ?? [] }, { groups: target.groups ?? [], tags: target.tags ?? [], os: target.os ?? [], kinds: target.kinds ?? [] }))
      .filter((d) => planItems(d, vulns.filter((v) => v.deviceId === d.id).map(asPlan), sel).items.length > 0)
      .map((d) => d.id);
    if (!ids.length) continue;
    const waiting = pending.find((x) => x.status === "attente_approbation");
    if (waiting) {
      await db.update(patchDeployment).set({ deviceIds: [...new Set([...waiting.deviceIds, ...ids])] }).where(eq(patchDeployment.id, waiting.id));
      continue;
    }
    await createDeployment(orgId, "système", {
      title: `${p.name} — ${new Date().toLocaleDateString("fr-FR", { day: "numeric", month: "short", year: "numeric" })}`,
      deviceIds: ids,
      selection: sel,
      window: p.window as Window | null,
      reboot: p.reboot as "immediat" | "fenetre" | "utilisateur",
      rebootDeferHours: p.rebootDeferHours,
      maxParallel: p.maxParallel,
      pilot: p.pilot,
      pilotThreshold: p.pilotThreshold,
      policyId: p.id,
      approval: p.approval === "auto" ? "auto" : "manuelle",
    });
    created++;
  }
  return created;
}

const asPlan = (v: typeof patchVuln.$inferSelect) => ({ cveId: v.cveId, status: v.status, priority: v.priority, kev: v.kev, fix: v.fix as unknown as Fix });

// ---------- Déploiements ----------

export interface DeploymentInput {
  title?: string;
  deviceIds: number[];
  selection: Selection;
  window: Window | null;
  reboot: "immediat" | "fenetre" | "utilisateur";
  rebootDeferHours?: number;
  maxParallel?: number;
  pilot: boolean;
  pilotThreshold?: number;
  policyId?: number | null;
  approval: "auto" | "manuelle";
}

/** Normalise une demande de déploiement saisie dans la console (« corriger maintenant »). */
export function deploymentFromRequest(b: Record<string, unknown>): DeploymentInput {
  const ids = Array.isArray(b.deviceIds) ? [...new Set(b.deviceIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))].slice(0, 2000) : [];
  if (!ids.length) throw new PatchError("Choisissez au moins un équipement.");
  const cves = Array.isArray(b.cves) ? b.cves.map(String).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)).slice(0, 500) : null;
  let window: Window | null = null;
  try {
    window = normalizeWindow(b.window);
  } catch (e) {
    throw new PatchError(msg(e));
  }
  const prio = ["urgente", "haute", "moyenne", "basse"].includes(String(b.minPriority)) ? (String(b.minPriority) as Selection["minPriority"]) : "basse";
  return {
    title: typeof b.title === "string" ? b.title.trim().slice(0, 120) : undefined,
    deviceIds: ids,
    selection: { content: b.content === "os" || b.content === "apps" ? b.content : "all", minPriority: prio, kevOnly: b.kevOnly === true, cves },
    window,
    reboot: b.reboot === "immediat" || b.reboot === "utilisateur" ? b.reboot : "fenetre",
    rebootDeferHours: Number(b.rebootDeferHours) > 0 ? Math.min(168, Number(b.rebootDeferHours)) : 24,
    maxParallel: Number(b.maxParallel) > 0 ? Math.min(500, Number(b.maxParallel)) : 20,
    pilot: b.pilot === true,
    pilotThreshold: Number(b.pilotThreshold) > 0 ? Math.min(100, Number(b.pilotThreshold)) : 100,
    approval: "auto",
  };
}

export async function createDeployment(orgId: string, actor: string, input: DeploymentInput): Promise<{ id: number; status: string; message: string }> {
  const db = getDb();
  const owned = await db
    .select({ id: patchDevice.id })
    .from(patchDevice)
    .where(and(eq(patchDevice.orgId, orgId), inArray(patchDevice.id, input.deviceIds)));
  if (!owned.length) throw new PatchError("Aucun des équipements choisis n’existe.", 404);
  const ids = owned.map((o) => o.id);
  const title =
    input.title ||
    (input.selection.cves?.length === 1 ? `Corriger ${input.selection.cves[0]}` : `Correctifs ${input.selection.content === "os" ? "système" : input.selection.content === "apps" ? "applications" : "système et applications"}`) +
      ` — ${ids.length} équipement${ids.length > 1 ? "s" : ""}`;
  const [dep] = await db
    .insert(patchDeployment)
    .values({
      orgId,
      policyId: input.policyId ?? null,
      title,
      status: input.approval === "manuelle" ? "attente_approbation" : "planifie",
      selection: input.selection as unknown as Record<string, unknown>,
      deviceIds: ids,
      window: input.window as unknown as Record<string, unknown> | null,
      reboot: input.reboot,
      rebootDeferHours: input.rebootDeferHours ?? 24,
      maxParallel: input.maxParallel ?? 20,
      pilot: input.pilot,
      pilotThreshold: input.pilotThreshold ?? 100,
      createdBy: actor,
      message: input.approval === "manuelle" ? "En attente d’approbation par un administrateur." : "",
    })
    .returning();
  await audit(orgId, actor, "deploiement_cree", title, { id: dep.id, devices: ids.length, approval: input.approval });
  if (input.approval === "manuelle") return { id: dep.id, status: dep.status, message: dep.message };
  return { id: dep.id, ...(await startDeployment(dep)) };
}

/** Crée les installations d'une phase ; renvoie le nombre de tâches créées (0 si tout est déjà à jour). */
async function createInstallJobs(dep: Deployment, devices: Device[], phase: "pilote" | "production"): Promise<number> {
  if (!devices.length) return 0;
  const db = getDb();
  const ids = devices.map((d) => d.id);
  const vulns = await db.select().from(patchVuln).where(and(inArray(patchVuln.deviceId, ids), eq(patchVuln.status, "ouverte")));
  const apps = await db
    .select({ deviceId: patchComponent.deviceId, name: patchComponent.name, version: patchComponent.version })
    .from(patchComponent)
    .where(and(inArray(patchComponent.deviceId, ids), eq(patchComponent.kind, "app")));
  const window = dep.window as Window | null;
  const notBefore = window ? nextWindowStart(window) : null;
  const sel = dep.selection as unknown as Selection;
  let n = 0;
  for (const d of devices) {
    const plan = planItems(d, vulns.filter((v) => v.deviceId === d.id).map(asPlan), sel);
    if (!plan.items.length) continue;
    const items: JobItem[] = plan.items.map((it) => {
      if (it.kind !== "winget") return it;
      const installed = apps.find((a) => a.deviceId === d.id && matchApp(a.name)?.winget === it.id);
      return installed?.version ? { ...it, from: installed.version } : it;
    });
    await db.insert(patchJob).values({
      orgId: dep.orgId,
      deviceId: d.id,
      deploymentId: dep.id,
      action: "install",
      phase,
      payload: { items, reboot: agentReboot(dep.reboot as "immediat" | "fenetre" | "utilisateur", d.kind, window), cves: plan.cves },
      notBefore,
    });
    n++;
  }
  return n;
}

async function finishDeployment(dep: Deployment, status: "termine" | "echec", message: string) {
  await getDb().update(patchDeployment).set({ status, message, finishedAt: new Date() }).where(eq(patchDeployment.id, dep.id));
  await audit(dep.orgId, "système", status === "termine" ? "deploiement_termine" : "deploiement_echec", dep.title, { id: dep.id, message });
}

async function startDeployment(dep: Deployment): Promise<{ status: string; message: string }> {
  const db = getDb();
  const devices = await db
    .select()
    .from(patchDevice)
    .where(and(eq(patchDevice.orgId, dep.orgId), inArray(patchDevice.id, dep.deviceIds)));
  const set = async (status: string, message: string) => {
    await db.update(patchDeployment).set({ status, message, startedAt: new Date() }).where(eq(patchDeployment.id, dep.id));
    return { status, message };
  };
  if (dep.pilot) {
    const pilots = devices.filter((d) => d.ring === "pilote");
    if (!pilots.length) {
      const m = "Aucun équipement de l’anneau pilote parmi les cibles : placez au moins un équipement dans l’anneau pilote, ou lancez le déploiement sans pilote.";
      await finishDeployment(dep, "echec", m);
      return { status: "echec", message: m };
    }
    const n = await createInstallJobs(dep, pilots, "pilote");
    if (n > 0) return set("pilote", `Anneau pilote : ${n} équipement${n > 1 ? "s" : ""} en cours. La production démarre si le pilote réussit.`);
    // Pilote déjà à jour : on passe directement à la production
  }
  const rest = dep.pilot ? devices.filter((d) => d.ring !== "pilote") : devices;
  const n = await createInstallJobs(dep, rest, "production");
  if (!n) {
    const m = "Rien à installer : les équipements visés n’ont pas de CVE correspondant à cette sélection.";
    await finishDeployment(dep, "termine", m);
    return { status: "termine", message: m };
  }
  return set("production", `${n} équipement${n > 1 ? "s" : ""} à corriger${dep.window ? " pendant la fenêtre de maintenance" : ""}.`);
}

/**
 * Fait avancer les déploiements actifs : tâches sans réponse en échec, verdict de l'anneau pilote (production ou
 * arrêt), fin du déploiement quand toutes les tâches sont terminées.
 */
export async function advanceDeployments(orgId?: string): Promise<void> {
  const db = getDb();
  const stale = new Date(Date.now() - JOB_TIMEOUT_MS);
  const timedOut = await db
    .update(patchJob)
    .set({ status: "echec", log: sql`${patchJob.log} || 'Pas de réponse de l’agent dans les 6 heures.'`, finishedAt: new Date() })
    .where(and(eq(patchJob.status, "envoye"), lt(patchJob.sentAt, stale), orgId ? eq(patchJob.orgId, orgId) : undefined))
    .returning();
  for (const j of timedOut) {
    const [d] = await db.select().from(patchDevice).where(eq(patchDevice.id, j.deviceId));
    if (d && j.action === "install") await createRollback(j, d, "auto");
  }
  const deps = await db
    .select()
    .from(patchDeployment)
    .where(and(inArray(patchDeployment.status, ["pilote", "production"]), orgId ? eq(patchDeployment.orgId, orgId) : undefined));
  for (const dep of deps) {
    const jobs = await db.select().from(patchJob).where(eq(patchJob.deploymentId, dep.id));
    const installs = jobs.filter((j) => j.action === "install");
    if (dep.status === "pilote") {
      const pilot = installs.filter((j) => j.phase === "pilote");
      const v = pilotVerdict(pilot, dep.pilotThreshold);
      if (v === "en_cours") continue;
      const ok = pilot.filter((j) => j.status === "succes").length;
      if (v === "echec") {
        await finishDeployment(dep, "echec", `Échec de l’anneau pilote (${ok}/${pilot.length} réussi${ok > 1 ? "s" : ""}, seuil ${dep.pilotThreshold} %) : déploiement arrêté, retour arrière lancé sur les équipements en échec.`);
        continue;
      }
      const devices = await db
        .select()
        .from(patchDevice)
        .where(and(eq(patchDevice.orgId, dep.orgId), inArray(patchDevice.id, dep.deviceIds), ne(patchDevice.ring, "pilote")));
      const n = await createInstallJobs(dep, devices, "production");
      if (!n) await finishDeployment(dep, "termine", `Pilote réussi (${ok}/${pilot.length}) ; aucun autre équipement à corriger.`);
      else {
        await db.update(patchDeployment).set({ status: "production", message: `Pilote réussi (${ok}/${pilot.length}) : ${n} équipement${n > 1 ? "s" : ""} en production.` }).where(eq(patchDeployment.id, dep.id));
        await audit(dep.orgId, "système", "pilote_reussi", dep.title, { id: dep.id, ok, total: pilot.length });
      }
      continue;
    }
    if (installs.some((j) => j.status === "en_attente" || j.status === "envoye")) continue;
    const ok = installs.filter((j) => j.status === "succes").length;
    const ko = installs.filter((j) => j.status === "echec").length;
    await finishDeployment(
      dep,
      "termine",
      `${ok} installation${ok > 1 ? "s" : ""} réussie${ok > 1 ? "s" : ""}${ko ? `, ${ko} échec${ko > 1 ? "s" : ""} (retour arrière lancé)` : ""}. Les CVE sont déclarées corrigées au prochain inventaire de chaque équipement.`,
    );
  }
}

export async function deploymentAction(orgId: string, actor: string, id: number, action: string) {
  const db = getDb();
  const [dep] = await db.select().from(patchDeployment).where(and(eq(patchDeployment.orgId, orgId), eq(patchDeployment.id, id)));
  if (!dep) throw new PatchError("Déploiement introuvable.", 404);
  if (action === "approve") {
    if (dep.status !== "attente_approbation") throw new PatchError("Ce déploiement n’attend pas d’approbation.");
    await db.update(patchDeployment).set({ approvedBy: actor, approvedAt: new Date(), status: "planifie" }).where(eq(patchDeployment.id, id));
    await audit(orgId, actor, "deploiement_approuve", dep.title, { id });
    return startDeployment({ ...dep, status: "planifie" });
  }
  if (action === "cancel") {
    if (!ACTIVE.includes(dep.status)) throw new PatchError("Ce déploiement est déjà terminé.");
    await db.update(patchJob).set({ status: "annule", finishedAt: new Date() }).where(and(eq(patchJob.deploymentId, id), eq(patchJob.status, "en_attente")));
    await db.update(patchDeployment).set({ status: "annule", message: `Annulé par ${actor}.`, finishedAt: new Date() }).where(eq(patchDeployment.id, id));
    await audit(orgId, actor, "deploiement_annule", dep.title, { id });
    return { status: "annule", message: "Déploiement annulé : les installations non commencées ne seront pas envoyées." };
  }
  if (action === "rollback") {
    const jobs = await db.select().from(patchJob).where(and(eq(patchJob.deploymentId, id), eq(patchJob.action, "install"), eq(patchJob.status, "succes")));
    let n = 0;
    for (const j of jobs) {
      const [d] = await db.select().from(patchDevice).where(eq(patchDevice.id, j.deviceId));
      if (d && (await createRollback(j, d, "manuel"))) n++;
    }
    await audit(orgId, actor, "retour_arriere_demande", dep.title, { id, jobs: n });
    return { status: dep.status, message: n ? `Retour arrière envoyé à ${n} équipement${n > 1 ? "s" : ""}.` : "Rien à annuler : aucune installation réussie avec un retour arrière possible." };
  }
  throw new PatchError("Action inconnue.");
}

export async function listDeployments(orgId: string, limit = 40) {
  const db = getDb();
  const deps = await db.select().from(patchDeployment).where(eq(patchDeployment.orgId, orgId)).orderBy(desc(patchDeployment.createdAt)).limit(limit);
  if (!deps.length) return [];
  const jobs = await db
    .select({ j: patchJob, name: patchDevice.name })
    .from(patchJob)
    .innerJoin(patchDevice, eq(patchDevice.id, patchJob.deviceId))
    .where(
      inArray(
        patchJob.deploymentId,
        deps.map((d) => d.id),
      ),
    )
    .orderBy(asc(patchJob.id));
  return deps.map((d) => ({
    id: d.id,
    title: d.title,
    status: d.status,
    message: d.message,
    policyId: d.policyId,
    selection: d.selection,
    window: d.window,
    reboot: d.reboot,
    pilot: d.pilot,
    pilotThreshold: d.pilotThreshold,
    devices: d.deviceIds.length,
    createdBy: d.createdBy,
    approvedBy: d.approvedBy,
    createdAt: d.createdAt.toISOString(),
    finishedAt: d.finishedAt?.toISOString() ?? null,
    jobs: jobs
      .filter((x) => x.j.deploymentId === d.id)
      .map(({ j, name }) => ({ id: j.id, device: name, deviceId: j.deviceId, action: j.action, phase: j.phase, status: j.status, cves: Array.isArray(j.payload.cves) ? (j.payload.cves as string[]).length : 0, log: j.log.slice(-1500), notBefore: j.notBefore?.toISOString() ?? null, finishedAt: j.finishedAt?.toISOString() ?? null })),
  }));
}

// ---------- Équipements (console) ----------

export async function listDevices(orgId: string) {
  const db = getDb();
  const rows = await db.select().from(patchDevice).where(eq(patchDevice.orgId, orgId)).orderBy(asc(patchDevice.name));
  const counts = await db
    .select({ d: patchVuln.deviceId, p: patchVuln.priority, kev: patchVuln.kev, n: sql<number>`count(*)::int`, fix: sql<number>`count(*) filter (where ${patchVuln.fix}->>'kind' <> 'none')::int` })
    .from(patchVuln)
    .where(and(eq(patchVuln.orgId, orgId), eq(patchVuln.status, "ouverte")))
    .groupBy(patchVuln.deviceId, patchVuln.priority, patchVuln.kev);
  const pending = await db
    .select({ d: patchJob.deviceId, n: sql<number>`count(*)::int` })
    .from(patchJob)
    .where(and(eq(patchJob.orgId, orgId), inArray(patchJob.status, ["en_attente", "envoye"])))
    .groupBy(patchJob.deviceId);
  return rows.map((d) => {
    const c = counts.filter((x) => x.d === d.id);
    const by = (p: string) => c.filter((x) => x.p === p).reduce((s, x) => s + x.n, 0);
    return {
      id: d.id,
      name: d.name,
      hostname: d.hostname,
      kind: d.kind,
      osFamily: d.osFamily,
      osName: d.osName,
      osVersion: d.osVersion,
      arch: d.arch,
      ip: d.ip,
      domain: d.domain,
      loggedUser: d.loggedUser,
      groupName: d.groupName,
      tags: d.tags ?? [],
      ring: d.ring,
      agentVersion: d.agentVersion,
      appManager: d.appManager,
      rebootPending: d.rebootPending,
      lastSeenAt: d.lastSeenAt?.toISOString() ?? null,
      lastInventoryAt: d.lastInventoryAt?.toISOString() ?? null,
      correlatedAt: d.correlatedAt?.toISOString() ?? null,
      correlateError: d.correlateError,
      enrolledAt: d.enrolledAt.toISOString(),
      vulns: { urgente: by("urgente"), haute: by("haute"), moyenne: by("moyenne"), basse: by("basse"), kev: c.filter((x) => x.kev).reduce((s, x) => s + x.n, 0), patchable: c.reduce((s, x) => s + x.fix, 0) },
      pendingJobs: pending.find((p) => p.d === d.id)?.n ?? 0,
    };
  });
}

export async function deviceDetail(orgId: string, id: number) {
  const db = getDb();
  const [d] = await db.select().from(patchDevice).where(and(eq(patchDevice.orgId, orgId), eq(patchDevice.id, id)));
  if (!d) throw new PatchError("Équipement introuvable.", 404);
  const [components, vulns, jobs, events] = await Promise.all([
    db.select().from(patchComponent).where(eq(patchComponent.deviceId, id)).orderBy(asc(patchComponent.kind), asc(patchComponent.name)),
    db.select().from(patchVuln).where(eq(patchVuln.deviceId, id)).orderBy(desc(patchVuln.score)),
    db.select().from(patchJob).where(eq(patchJob.deviceId, id)).orderBy(desc(patchJob.id)).limit(40),
    db.select().from(patchAudit).where(and(eq(patchAudit.orgId, orgId), eq(patchAudit.target, d.name))).orderBy(desc(patchAudit.at)).limit(30),
  ]);
  return {
    device: (await listDevices(orgId)).find((x) => x.id === id)!,
    hardware: d.hardware,
    components: components.map((c) => ({ kind: c.kind, name: c.name, vendor: c.vendor, version: c.version, source: c.source, extra: c.extra, catalog: c.kind === "app" ? (matchApp(c.name)?.label ?? null) : null })),
    vulns: vulns.map(vulnView),
    jobs: jobs.map((j) => ({ id: j.id, action: j.action, phase: j.phase, status: j.status, deploymentId: j.deploymentId, payload: j.payload, log: j.log.slice(-4000), result: j.result, createdAt: j.createdAt.toISOString(), sentAt: j.sentAt?.toISOString() ?? null, finishedAt: j.finishedAt?.toISOString() ?? null, notBefore: j.notBefore?.toISOString() ?? null })),
    events: events.map((e) => ({ actor: e.actor, action: e.action, detail: e.detail, at: e.at.toISOString() })),
  };
}

const vulnView = (v: typeof patchVuln.$inferSelect) => ({
  id: v.id,
  deviceId: v.deviceId,
  cveId: v.cveId,
  componentKind: v.componentKind,
  componentName: v.componentName,
  componentVersion: v.componentVersion,
  source: v.source,
  advisory: v.advisory,
  cvss: v.cvss,
  epss: v.epss,
  kev: v.kev,
  ransomware: v.ransomware,
  score: v.score,
  priority: v.priority,
  reasons: v.reasons,
  fix: v.fix,
  status: v.status,
  ignoredReason: v.ignoredReason,
  ignoredBy: v.ignoredBy,
  firstSeen: v.firstSeen.toISOString(),
  fixedAt: v.fixedAt?.toISOString() ?? null,
});

export async function updateDevice(orgId: string, actor: string, id: number, b: Record<string, unknown>) {
  const db = getDb();
  const [d] = await db.select().from(patchDevice).where(and(eq(patchDevice.orgId, orgId), eq(patchDevice.id, id)));
  if (!d) throw new PatchError("Équipement introuvable.", 404);
  if (b.action === "scan") {
    await db.update(patchDevice).set({ inventoryRequested: true }).where(eq(patchDevice.id, id));
    await db.insert(patchJob).values({ orgId, deviceId: id, action: "scan", payload: {} });
    await audit(orgId, actor, "scan_demande", d.name);
    return { message: "Scan demandé : il démarre à la prochaine synchronisation de l’agent (moins d’une minute s’il est en ligne)." };
  }
  if (b.action === "reboot") {
    await db.insert(patchJob).values({ orgId, deviceId: id, action: "reboot", payload: { force: b.force === true, reason: "Demande depuis la console" } });
    await audit(orgId, actor, "redemarrage_demande", d.name);
    return { message: "Redémarrage demandé (avec un préavis de 5 minutes pour l’utilisateur)." };
  }
  const set: Partial<typeof patchDevice.$inferInsert> = {};
  if (typeof b.name === "string" && b.name.trim()) set.name = b.name.trim().slice(0, 80);
  if (typeof b.groupName === "string") set.groupName = b.groupName.trim().slice(0, 60);
  if (Array.isArray(b.tags)) set.tags = [...new Set(b.tags.map((t) => String(t).trim().slice(0, 30)).filter(Boolean))].slice(0, 20);
  if (b.ring === "pilote" || b.ring === "production") set.ring = b.ring;
  if (!Object.keys(set).length) throw new PatchError("Rien à modifier.");
  await db.update(patchDevice).set(set).where(eq(patchDevice.id, id));
  await audit(orgId, actor, "equipement_modifie", d.name, set as Record<string, unknown>);
  return { message: "Équipement mis à jour." };
}

export async function deleteDevice(orgId: string, actor: string, id: number) {
  const r = await getDb()
    .delete(patchDevice)
    .where(and(eq(patchDevice.orgId, orgId), eq(patchDevice.id, id)))
    .returning({ name: patchDevice.name });
  if (r.length) await audit(orgId, actor, "equipement_supprime", r[0].name);
}

// ---------- Vulnérabilités du parc ----------

export async function fleetVulns(orgId: string, status = "ouverte") {
  const rows = await getDb()
    .select({ v: patchVuln, device: patchDevice.name })
    .from(patchVuln)
    .innerJoin(patchDevice, eq(patchDevice.id, patchVuln.deviceId))
    .where(and(eq(patchVuln.orgId, orgId), status === "toutes" ? undefined : eq(patchVuln.status, status)))
    .orderBy(desc(patchVuln.score))
    .limit(20000);
  const by = new Map<
    string,
    { cveId: string; score: number; priority: string; cvss: number | null; epss: number | null; kev: boolean; ransomware: boolean; reasons: string[]; components: Set<string>; fixes: Set<string>; patchable: boolean; devices: { id: number; name: string; vulnId: number; component: string; version: string; status: string; fix: string }[] }
  >();
  for (const { v, device } of rows) {
    let e = by.get(v.cveId);
    if (!e) {
      e = { cveId: v.cveId, score: v.score, priority: v.priority, cvss: v.cvss, epss: v.epss, kev: v.kev, ransomware: v.ransomware, reasons: v.reasons, components: new Set(), fixes: new Set(), patchable: false, devices: [] };
      by.set(v.cveId, e);
    }
    const fix = v.fix as unknown as Fix;
    e.components.add(v.componentName);
    if (fix.label) e.fixes.add(fix.fixedVersion ? `${fix.label} (${fix.fixedVersion})` : fix.label);
    e.patchable = e.patchable || fix.kind !== "none";
    e.devices.push({ id: v.deviceId, name: device, vulnId: v.id, component: v.componentName, version: v.componentVersion, status: v.status, fix: fix.kind });
  }
  return [...by.values()].map((e) => ({ ...e, components: [...e.components], fixes: [...e.fixes] }));
}

export async function setVulnStatus(orgId: string, actor: string, b: Record<string, unknown>) {
  const cveId = String(b.cveId ?? "").toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) throw new PatchError("CVE invalide.");
  const deviceId = b.deviceId == null ? null : Number(b.deviceId);
  const db = getDb();
  const where = and(eq(patchVuln.orgId, orgId), eq(patchVuln.cveId, cveId), deviceId ? eq(patchVuln.deviceId, deviceId) : undefined);
  if (b.action === "ignore") {
    const reason = String(b.reason ?? "").trim().slice(0, 300);
    if (reason.length < 5) throw new PatchError("Indiquez la raison (5 caractères au moins) : elle est conservée dans le journal d’audit.");
    const r = await db.update(patchVuln).set({ status: "ignoree", ignoredReason: reason, ignoredBy: actor }).where(and(where, eq(patchVuln.status, "ouverte"))).returning({ id: patchVuln.id });
    await audit(orgId, actor, "cve_ignoree", cveId, { reason, deviceId, count: r.length });
    return { count: r.length };
  }
  if (b.action === "reopen") {
    const r = await db.update(patchVuln).set({ status: "ouverte", ignoredReason: null, ignoredBy: null }).where(and(where, eq(patchVuln.status, "ignoree"))).returning({ id: patchVuln.id });
    await audit(orgId, actor, "cve_reouverte", cveId, { deviceId, count: r.length });
    return { count: r.length };
  }
  throw new PatchError("Action inconnue.");
}

// ---------- Logiciels et vue d'ensemble ----------

export async function software(orgId: string, q = "") {
  const like = q.trim() ? `%${q.trim().slice(0, 60)}%` : null;
  const rows = await getDb()
    .select({ kind: patchComponent.kind, name: patchComponent.name, version: patchComponent.version, vendor: sql<string>`max(${patchComponent.vendor})`, n: sql<number>`count(distinct ${patchComponent.deviceId})::int` })
    .from(patchComponent)
    .innerJoin(patchDevice, eq(patchDevice.id, patchComponent.deviceId))
    .where(and(eq(patchDevice.orgId, orgId), like ? sql`${patchComponent.name} ilike ${like}` : inArray(patchComponent.kind, ["os", "app"])))
    .groupBy(patchComponent.kind, patchComponent.name, patchComponent.version)
    .orderBy(desc(sql`count(distinct ${patchComponent.deviceId})`), asc(patchComponent.name))
    .limit(400);
  return rows.map((r) => ({ ...r, catalog: r.kind === "app" ? (matchApp(r.name)?.label ?? null) : null }));
}

export async function overview(orgId: string) {
  const db = getDb();
  await advanceDeployments(orgId).catch((e) => console.error(`[parc] avancement : ${msg(e)}`));
  const [devices, deployments, policies, enroll, trend, mttr, jobsStats, events] = await Promise.all([
    listDevices(orgId),
    listDeployments(orgId, 20),
    listPolicies(orgId),
    getEnrollment(orgId),
    db.execute(sql`
      select to_char(d, 'YYYY-MM-DD') as day,
        count(v.id) filter (where v.priority in ('urgente','haute'))::int as high,
        count(v.id)::int as total
      from generate_series(current_date - 89, current_date, interval '1 day') d
      left join patch_vuln v on v.user_id = ${orgId} and v.status <> 'ignoree'
        and v.first_seen < d + interval '1 day' and (v.fixed_at is null or v.fixed_at >= d + interval '1 day')
      group by d order by d`),
    db.execute(sql`
      select avg(extract(epoch from (fixed_at - first_seen)) / 86400)::float as days, count(*)::int as n
      from patch_vuln where user_id = ${orgId} and status = 'corrigee' and priority in ('urgente','haute') and fixed_at > now() - interval '90 days'`),
    db.execute(sql`
      select count(*) filter (where status = 'succes')::int as ok, count(*) filter (where status = 'echec')::int as ko
      from patch_job where user_id = ${orgId} and action = 'install' and finished_at > now() - interval '90 days'`),
    db.select().from(patchAudit).where(eq(patchAudit.orgId, orgId)).orderBy(desc(patchAudit.at)).limit(25),
  ]);
  const now = Date.now();
  const online = devices.filter((d) => d.lastSeenAt && now - Date.parse(d.lastSeenAt) < ONLINE_MS).length;
  const compliant = devices.filter((d) => d.lastInventoryAt && d.vulns.urgente === 0 && d.vulns.kev === 0).length;
  const inventoried = devices.filter((d) => d.lastInventoryAt).length;
  const cves = await db
    .select({ p: patchVuln.priority, kev: patchVuln.kev, n: sql<number>`count(distinct ${patchVuln.cveId})::int`, rows: sql<number>`count(*)::int` })
    .from(patchVuln)
    .where(and(eq(patchVuln.orgId, orgId), eq(patchVuln.status, "ouverte")))
    .groupBy(patchVuln.priority, patchVuln.kev);
  const sum = (f: (x: (typeof cves)[number]) => boolean, k: "n" | "rows" = "n") => cves.filter(f).reduce((s, x) => s + x[k], 0);
  const m = (mttr as unknown as { days: number | null; n: number }[])[0];
  const js = (jobsStats as unknown as { ok: number; ko: number }[])[0];
  return {
    kpis: {
      devices: devices.length,
      online,
      inventoried,
      compliance: inventoried ? Math.round((compliant / inventoried) * 100) : null,
      openCves: sum(() => true),
      openRows: sum(() => true, "rows"),
      urgent: sum((x) => x.p === "urgente"),
      high: sum((x) => x.p === "haute"),
      kev: sum((x) => x.kev),
      rebootPending: devices.filter((d) => d.rebootPending).length,
      mttrDays: m?.n ? Math.round(m.days! * 10) / 10 : null,
      deploySuccess: js && js.ok + js.ko ? Math.round((js.ok / (js.ok + js.ko)) * 100) : null,
    },
    trend: (trend as unknown as { day: string; high: number; total: number }[]).map((t) => ({ day: t.day, high: t.high, total: t.total })),
    devices,
    deployments,
    policies,
    enrollment: enroll ? { createdAt: enroll.createdAt } : null,
    agentVersion: AGENT_VERSION,
    events: events.map((e) => ({ actor: e.actor, action: e.action, target: e.target, detail: e.detail, at: e.at.toISOString() })),
  };
}

// ---------- Passe quotidienne ----------

/**
 * Chaque matin : nouvelle corrélation des équipements (nouvelles CVE publiées, scores EPSS et KEV à jour), politiques
 * automatiques, avancement des déploiements, purge (journal d'un an, cache inutilisé depuis 30 jours).
 */
export async function patchDaily(budgetMs = 240_000): Promise<Record<string, unknown>> {
  if (!dbConfigured()) return {};
  const db = getDb();
  const t0 = Date.now();
  const devices = await db
    .select({ id: patchDevice.id, orgId: patchDevice.orgId })
    .from(patchDevice)
    .where(sql`${patchDevice.lastInventoryAt} is not null`)
    .orderBy(sql`${patchDevice.correlatedAt} asc nulls first`);
  let correlated = 0;
  for (const d of devices) {
    if (Date.now() - t0 > budgetMs) break;
    try {
      await correlateDevice(d.id);
      correlated++;
    } catch (e) {
      console.error(`[parc] corrélation ${d.id} : ${msg(e)}`);
    }
  }
  const users = [...new Set(devices.map((d) => d.orgId))];
  let deployments = 0;
  for (const u of users) {
    try {
      deployments += await runPolicies(u);
    } catch (e) {
      console.error(`[parc] politiques ${u} : ${msg(e)}`);
    }
  }
  await advanceDeployments();
  await db.delete(patchAudit).where(lt(patchAudit.at, new Date(Date.now() - 365 * 86_400_000)));
  await db.delete(patchCache).where(lt(patchCache.fetchedAt, new Date(Date.now() - 30 * 86_400_000)));
  return { devices: devices.length, correlated, deployments };
}

/** Export CSV des CVE ouvertes du parc (une ligne par équipement et par CVE). */
export async function exportCsv(orgId: string): Promise<string> {
  const rows = await getDb()
    .select({ v: patchVuln, device: patchDevice.name, os: patchDevice.osName })
    .from(patchVuln)
    .innerJoin(patchDevice, eq(patchDevice.id, patchVuln.deviceId))
    .where(and(eq(patchVuln.orgId, orgId), ne(patchVuln.status, "corrigee")))
    .orderBy(desc(patchVuln.score));
  const esc = (s: unknown) => {
    const t = String(s ?? "");
    return /[";\n\r]/.test(t) || /^[=+\-@]/.test(t) ? `"${t.replace(/^([=+\-@])/, "'$1").replace(/"/g, '""')}"` : t;
  };
  const head = ["Équipement", "Système", "CVE", "Priorité", "Score", "CVSS", "EPSS", "Exploitée (KEV)", "Composant", "Version", "Correctif", "Version corrigée", "Statut", "Détectée le"];
  const lines = rows.map(({ v, device, os }) => {
    const fix = v.fix as unknown as Fix;
    return [device, os, v.cveId, v.priority, v.score, v.cvss ?? "", v.epss != null ? (v.epss * 100).toFixed(1) + " %" : "", v.kev ? "oui" : "non", v.componentName, v.componentVersion, fix.label ?? "", fix.fixedVersion ?? "", v.status, v.firstSeen.toISOString().slice(0, 10)].map(esc).join(";");
  });
  return "﻿" + [head.join(";"), ...lines].join("\r\n");
}


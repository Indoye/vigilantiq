/**
 * Parc & correctifs — règles de déploiement (pures) : validation des politiques, ciblage des équipements,
 * fenêtres de maintenance (fuseau horaire), choix des correctifs, redémarrage, anneau pilote.
 */
import { PRIORITY_ORDER } from "../score.ts";
import type { Priority } from "../types.ts";

export type Content = "os" | "apps" | "all";
export type Approval = "auto" | "manuelle";
export type RebootMode = "immediat" | "fenetre" | "utilisateur";
/** Consigne envoyée à l'agent : redémarrer si nécessaire, prévenir l'utilisateur, ou ne rien faire. */
export type AgentReboot = "redemarrer" | "prevenir" | "aucun";

export interface Window {
  /** 1 = lundi … 7 = dimanche */
  days: number[];
  start: string;
  end: string;
  tz: string;
}

export interface PolicyInput {
  name: string;
  enabled: boolean;
  target: { groups: string[]; tags: string[]; os: string[]; kinds: string[] };
  content: Content;
  minPriority: Priority;
  kevOnly: boolean;
  approval: Approval;
  window: Window | null;
  reboot: RebootMode;
  rebootDeferHours: number;
  maxParallel: number;
  pilot: boolean;
  pilotThreshold: number;
}

export class PolicyError extends Error {}

const HHMM = /^([01]\d|2[0-3]):([0-5]\d)$/;
const strList = (v: unknown, max = 30) =>
  Array.isArray(v)
    ? [...new Set(v.map((x) => String(x ?? "").trim().slice(0, 60)).filter(Boolean))].slice(0, max)
    : [];
const oneOf = <T extends string>(v: unknown, list: readonly T[], def: T): T => (list.includes(v as T) ? (v as T) : def);
const int = (v: unknown, min: number, max: number, def: number) => {
  const n = Number(v);
  return Number.isInteger(n) ? Math.min(max, Math.max(min, n)) : def;
};

export function validTimeZone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat("en-GB", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

export function normalizeWindow(v: unknown): Window | null {
  if (v == null || v === false) return null;
  const w = v as Record<string, unknown>;
  const days = [...new Set((Array.isArray(w.days) ? w.days : []).map(Number).filter((d) => Number.isInteger(d) && d >= 1 && d <= 7))].sort();
  const start = String(w.start ?? "");
  const end = String(w.end ?? "");
  const tz = String(w.tz ?? "UTC");
  if (!days.length) throw new PolicyError("Choisissez au moins un jour pour la fenêtre de maintenance.");
  if (!HHMM.test(start) || !HHMM.test(end) || start === end) throw new PolicyError("Heures de la fenêtre invalides (format HH:MM, début différent de la fin).");
  if (!validTimeZone(tz)) throw new PolicyError("Fuseau horaire inconnu.");
  return { days, start, end, tz };
}

/** Vérifie et complète une politique saisie dans la console. */
export function normalizePolicy(raw: unknown): PolicyInput {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const name = String(r.name ?? "").trim().slice(0, 80);
  if (!name) throw new PolicyError("Nom de la politique obligatoire.");
  const t = (r.target && typeof r.target === "object" ? r.target : {}) as Record<string, unknown>;
  return {
    name,
    enabled: r.enabled !== false,
    target: { groups: strList(t.groups), tags: strList(t.tags), os: strList(t.os).filter((o) => o === "windows" || o === "linux" || o === "macos"), kinds: strList(t.kinds).filter((k) => k === "poste" || k === "serveur") },
    content: oneOf(r.content, ["os", "apps", "all"] as const, "all"),
    minPriority: oneOf(r.minPriority, PRIORITY_ORDER, "haute"),
    kevOnly: r.kevOnly === true,
    approval: oneOf(r.approval, ["auto", "manuelle"] as const, "manuelle"),
    window: normalizeWindow(r.window),
    reboot: oneOf(r.reboot, ["immediat", "fenetre", "utilisateur"] as const, "fenetre"),
    rebootDeferHours: int(r.rebootDeferHours, 1, 168, 24),
    maxParallel: int(r.maxParallel, 1, 500, 20),
    pilot: r.pilot !== false,
    pilotThreshold: int(r.pilotThreshold, 1, 100, 100),
  };
}

// ---------- Ciblage ----------

export interface DeviceFacts {
  id: number;
  osFamily: string;
  kind: string;
  groupName: string;
  tags: string[];
  ring: string;
  appManager: boolean;
}

/** L'équipement est-il visé ? Une liste vide ne filtre pas ; les listes se combinent (ET). */
export function deviceMatches(d: DeviceFacts, t: PolicyInput["target"]): boolean {
  if (t.os.length && !t.os.includes(d.osFamily)) return false;
  if (t.kinds.length && !t.kinds.includes(d.kind)) return false;
  if (t.groups.length && !t.groups.some((g) => g.toLowerCase() === d.groupName.toLowerCase())) return false;
  if (t.tags.length && !t.tags.some((g) => d.tags.map((x) => x.toLowerCase()).includes(g.toLowerCase()))) return false;
  return true;
}

// ---------- Fenêtres de maintenance ----------

const DAY_IDX: Record<string, number> = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
function localParts(date: Date, tz: string): { day: number; minutes: number } {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: tz, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(date);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  return { day: DAY_IDX[get("weekday")] ?? 1, minutes: Number(get("hour")) * 60 + Number(get("minute")) };
}
const mins = (hhmm: string) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));

/** La date tombe-t-elle dans la fenêtre ? Une fenêtre qui passe minuit appartient au jour où elle commence. */
export function inWindow(w: Window | null, date = new Date()): boolean {
  if (!w) return true;
  const { day, minutes } = localParts(date, w.tz);
  const s = mins(w.start);
  const e = mins(w.end);
  if (s < e) return w.days.includes(day) && minutes >= s && minutes < e;
  if (minutes >= s) return w.days.includes(day);
  if (minutes < e) return w.days.includes(day === 1 ? 7 : day - 1);
  return false;
}

/** Prochaine ouverture de la fenêtre (à la minute près), dans les 8 jours ; maintenant si elle est ouverte. */
export function nextWindowStart(w: Window | null, from = new Date()): Date | null {
  if (!w) return from;
  if (inWindow(w, from)) return from;
  const t = new Date(Math.ceil(from.getTime() / 60_000) * 60_000);
  for (let i = 0; i < 8 * 24 * 60; i += 1) {
    const d = new Date(t.getTime() + i * 60_000);
    if (inWindow(w, d)) return d;
  }
  return null;
}

export function windowLabel(w: Window | null): string {
  if (!w) return "À tout moment";
  const names = ["", "lun", "mar", "mer", "jeu", "ven", "sam", "dim"];
  const days = w.days.length === 7 ? "tous les jours" : w.days.map((d) => names[d]).join(", ");
  return `${days}, ${w.start}–${w.end} (${w.tz})`;
}

// ---------- Choix des correctifs ----------

/** Correctif qui ferme une CVE sur un équipement (forme stockée avec la vulnérabilité). */
export interface Fix {
  /**
   * windows : mise à jour cumulative ; app : application tierce (winget) ; package : paquet Linux ;
   * macos : mises à jour Apple (softwareupdate) ; brew : formule ou cask Homebrew ; none : pas de correctif automatique
   */
  kind: "windows" | "app" | "package" | "macos" | "brew" | "none";
  label: string;
  fixedVersion?: string | null;
  winget?: string;
  package?: string;
  binaries?: string[];
  /** Homebrew : nom de la formule ou du cask */
  brew?: string;
  cask?: boolean;
}

export interface VulnForPlan {
  cveId: string;
  status: string;
  priority: string;
  kev: boolean;
  fix: Fix;
}

export interface Selection {
  content: Content;
  minPriority: Priority;
  kevOnly: boolean;
  /** Restreint à ces CVE (déploiement manuel « corriger cette CVE ») */
  cves?: string[] | null;
}

/** Élément à installer. `from` : version installée avant la mise à jour (pour le retour arrière). */
export type JobItem =
  | { kind: "windows"; categories: string[] }
  | { kind: "winget"; id: string; name: string; from?: string }
  | { kind: "package"; name: string; binaries: string[] }
  | { kind: "macos" }
  | { kind: "brew"; name: string; cask: boolean };

const rank = (p: string) => {
  const i = PRIORITY_ORDER.indexOf(p as Priority);
  return i < 0 ? PRIORITY_ORDER.length : i;
};

export function eligible(v: VulnForPlan, sel: Selection, d: Pick<DeviceFacts, "osFamily" | "appManager">): boolean {
  if (v.status !== "ouverte") return false;
  if (sel.cves?.length && !sel.cves.includes(v.cveId)) return false;
  if (rank(v.priority) > rank(sel.minPriority)) return false;
  if (sel.kevOnly && !v.kev) return false;
  if (v.fix.kind === "windows") return sel.content !== "apps" && d.osFamily === "windows";
  if (v.fix.kind === "package") return sel.content !== "apps" && d.osFamily === "linux" && Boolean(v.fix.binaries?.length);
  if (v.fix.kind === "app") return sel.content !== "os" && d.appManager && Boolean(v.fix.winget);
  if (v.fix.kind === "macos") return sel.content !== "apps" && d.osFamily === "macos";
  if (v.fix.kind === "brew") return sel.content !== "os" && d.osFamily === "macos" && d.appManager && Boolean(v.fix.brew);
  return false;
}

/** Ce que l'agent doit installer sur un équipement pour fermer les CVE retenues. */
export function planItems(d: Pick<DeviceFacts, "osFamily" | "appManager">, vulns: VulnForPlan[], sel: Selection): { items: JobItem[]; cves: string[] } {
  const keep = vulns.filter((v) => eligible(v, sel, d));
  const items: JobItem[] = [];
  if (keep.some((v) => v.fix.kind === "windows")) items.push({ kind: "windows", categories: ["security", "critical"] });
  if (keep.some((v) => v.fix.kind === "macos")) items.push({ kind: "macos" });
  const brews = new Map<string, boolean>();
  for (const v of keep) if (v.fix.kind === "brew" && v.fix.brew) brews.set(v.fix.brew, Boolean(v.fix.cask));
  const apps = new Map<string, string>();
  const pkgs = new Map<string, Set<string>>();
  for (const v of keep) {
    if (v.fix.kind === "app" && v.fix.winget) apps.set(v.fix.winget, v.fix.label);
    if (v.fix.kind === "package" && v.fix.package) {
      const s = pkgs.get(v.fix.package) ?? new Set<string>();
      for (const b of v.fix.binaries ?? []) s.add(b);
      pkgs.set(v.fix.package, s);
    }
  }
  for (const [id, name] of [...apps.entries()].sort()) items.push({ kind: "winget", id, name });
  for (const [name, bins] of [...pkgs.entries()].sort()) items.push({ kind: "package", name, binaries: [...bins].sort() });
  for (const [name, cask] of [...brews.entries()].sort()) items.push({ kind: "brew", name, cask });
  return { items, cves: [...new Set(keep.map((v) => v.cveId))].sort() };
}

// ---------- Redémarrage ----------

/**
 * Consigne de redémarrage pour un équipement. Un serveur ne redémarre jamais hors fenêtre : sans fenêtre, il ne
 * redémarre pas (le redémarrage en attente est signalé dans la console). Sur un poste, « fenêtre » sans fenêtre
 * définie revient à prévenir l'utilisateur.
 */
export function agentReboot(mode: RebootMode, kind: string, w: Window | null): AgentReboot {
  if (kind === "serveur") return w && mode !== "utilisateur" ? "redemarrer" : "aucun";
  if (mode === "utilisateur") return "prevenir";
  if (mode === "fenetre" && !w) return "prevenir";
  return "redemarrer";
}

// ---------- Anneau pilote ----------

/**
 * Verdict de l'anneau pilote : en cours tant qu'une tâche n'est pas terminée ; réussi si la part de succès atteint
 * le seuil (en %) ; sinon échec, qui arrête le déploiement.
 */
export function pilotVerdict(jobs: { status: string }[], threshold: number): "en_cours" | "ok" | "echec" {
  if (jobs.some((j) => j.status === "en_attente" || j.status === "envoye")) return "en_cours";
  const ok = jobs.filter((j) => j.status === "succes").length;
  const ko = jobs.filter((j) => j.status === "echec").length;
  if (ok + ko === 0) return "echec";
  return (ok / (ok + ko)) * 100 >= threshold ? "ok" : "echec";
}

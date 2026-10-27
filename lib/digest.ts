import { PRIORITY_LABEL } from "./score.ts";
import { matchStack, parseStack } from "./stack.ts";
import type { Feed, Priority, Vuln } from "./types.ts";
import { affectedSummary } from "./versions.ts";

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const RANK: Record<Priority, number> = { urgente: 0, haute: 1, moyenne: 2, basse: 3 };

export interface DigestPrefs {
  minPriority?: Priority;
  stackOnly?: boolean;
  /** CVE déjà traitées ou non concernées : exclues */
  closed?: Set<string>;
}

/**
 * Vulnérabilités retenues pour un digest :
 * - les failles exploitées activement, toujours ;
 * - celles de la stack à partir de la priorité moyenne ;
 * - sauf « seulement ma stack », toutes celles qui atteignent la priorité minimale choisie.
 */
export function selectForDigest(feed: Feed, stackRaw: string, prefs: DigestPrefs = {}, max = 25): (Vuln & { matches: string[] })[] {
  const stack = parseStack(stackRaw);
  const min = RANK[prefs.minPriority ?? "urgente"];
  return feed.vulns
    .map((v) => ({ ...v, matches: matchStack(v, stack) }))
    .filter((v) => !prefs.closed?.has(v.id))
    .filter((v) => {
      const exploited = Boolean(v.kev) || v.ssvc?.exploitation === "active";
      if (exploited) return true;
      if (v.matches.length > 0 && RANK[v.priority] <= RANK.moyenne) return true;
      return !prefs.stackOnly && RANK[v.priority] <= min;
    })
    .slice(0, max);
}

function line(v: Vuln & { matches: string[] }): string {
  return v.ai?.resume || v.description.slice(0, 220);
}

export function digestSubject(items: Vuln[], date: Date): string {
  const urgent = items.filter((v) => v.priority === "urgente").length;
  const d = date.toLocaleDateString("fr-FR", { day: "numeric", month: "long", timeZone: "UTC" });
  return `Veille CVE du ${d} : ${urgent} urgente${urgent > 1 ? "s" : ""}, ${items.length} à examiner`;
}

export function digestHtml(items: (Vuln & { matches: string[] })[], appUrl: string, name?: string): string {
  const colors: Record<string, string> = { urgente: "#D70015", haute: "#C93400", moyenne: "#0066CC", basse: "#545458" };
  const font = "-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif";
  const base = appUrl.replace(/\/$/, "");
  const rows = items
    .map(
      (v) => `
    <tr><td style="padding:16px 0;border-top:1px solid #E5E5EA">
      <div style="font:600 15px ${font};color:#1C1C1E">
        <span style="color:${colors[v.priority]}">${PRIORITY_LABEL[v.priority]}</span>
        &nbsp;<a href="${esc(base)}/cve/${v.id}" style="color:#1C1C1E">${v.id}</a>
        ${v.kev || v.ssvc?.exploitation === "active" ? '&nbsp;<span style="background:#FFD60A;color:#1C1C1E;padding:1px 7px;border-radius:5px;font-size:12px">Exploitée</span>' : ""}
      </div>
      <div style="font:14px/1.5 ${font};color:#3A3A3C;margin-top:4px">${esc(line(v))}</div>
      ${v.affected.length ? `<div style="font:14px/1.5 ${font};color:#3A3A3C;margin-top:4px"><b>Versions impactées :</b> ${esc(affectedSummary(v.affected, 3))}</div>` : ""}
      ${v.ai?.action ? `<div style="font:14px/1.5 ${font};color:#3A3A3C;margin-top:4px"><b>À faire :</b> ${esc(v.ai.action)}</div>` : ""}
      <div style="font:12px ${font};color:#6C6C70;margin-top:4px">
        Score ${v.score}/100${v.cvss != null ? `, CVSS ${v.cvss.toFixed(1)}` : ""}${v.epss != null ? `, EPSS ${(v.epss * 100).toFixed(1)} %` : ""}${v.matches.length ? `, votre stack : ${esc(v.matches.join(", "))}` : ""}
      </div>
    </td></tr>`,
    )
    .join("");
  return `<!doctype html><html><body style="margin:0;background:#F2F2F7">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
  <table width="100%" style="max-width:640px;background:#FFFFFF;border-radius:18px;padding:24px" cellpadding="0" cellspacing="0">
    <tr><td style="font:700 22px ${font};color:#1C1C1E;padding-bottom:4px">${name ? `Bonjour ${esc(name.split(" ")[0])}, voici` : "Voici"} les vulnérabilités à traiter</td></tr>
    <tr><td style="font:14px ${font};color:#6C6C70;padding-bottom:12px">Sélection selon votre stack et vos préférences.</td></tr>
    ${rows || `<tr><td style="font:14px ${font};color:#3A3A3C">Rien d'urgent ni de lié à votre stack sur les dernières 24 heures.</td></tr>`}
    <tr><td style="padding-top:18px;font:14px ${font}"><a href="${esc(base)}/" style="color:#0066CC;font-weight:600">Ouvrir le tableau de veille</a></td></tr>
    <tr><td style="padding-top:8px;font:12px ${font};color:#6C6C70">Pour changer ou couper ce digest : <a href="${esc(base)}/compte" style="color:#0066CC">Mon compte</a>.</td></tr>
  </table></td></tr></table></body></html>`;
}

export function digestSlack(items: (Vuln & { matches: string[] })[], appUrl: string, subject: string): string {
  const lines = items.map(
    (v) =>
      `• *${PRIORITY_LABEL[v.priority]}* <https://nvd.nist.gov/vuln/detail/${v.id}|${v.id}>${v.kev ? " :rotating_light: exploitée" : ""} (score ${v.score}) : ${line(v)}`,
  );
  return [`*${subject}*`, ...(lines.length ? lines : ["Rien d'urgent ni de lié à votre stack."]), `<${appUrl}|Ouvrir le tableau de veille>`].join("\n");
}

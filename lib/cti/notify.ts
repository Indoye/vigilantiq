/** E-mail des nouvelles alertes de renseignement (passe quotidienne). */
import type { AlertRow } from "./store.ts";

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const SEV_COLOR: Record<string, string> = { critique: "#D70015", haute: "#C93400", moyenne: "#0066CC", info: "#6C6C70" };
const SEV_ORDER = ["critique", "haute", "moyenne", "info"];
export const SOURCE_LABEL: Record<string, string> = {
  ransomware: "Site de rançongiciel",
  infostealer: "Identifiants volés (infostealer)",
  breach: "Fuite de données",
  typosquat: "Domaine ressemblant",
  phishing: "Hameçonnage",
  email: "Adresse dans une fuite",
  account: "Compte exposé",
};

export function ctiSubject(alerts: AlertRow[]): string {
  const crit = alerts.filter((a) => a.severity === "critique").length;
  return `VigilantIQ : ${alerts.length} nouvelle${alerts.length > 1 ? "s" : ""} alerte${alerts.length > 1 ? "s" : ""} de surveillance${crit ? ` dont ${crit} critique${crit > 1 ? "s" : ""}` : ""}`;
}

export function ctiHtml(alerts: AlertRow[], appUrl: string, name: string): string {
  const sorted = [...alerts].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)).slice(0, 30);
  const rows = sorted
    .map(
      (a) => `<tr><td style="padding:12px 0;border-bottom:1px solid #E5E5EA">
<div style="font-size:12px;font-weight:600;color:${SEV_COLOR[a.severity] ?? "#6C6C70"};text-transform:uppercase;letter-spacing:.03em">${esc(a.severity)} · ${esc(SOURCE_LABEL[a.source] ?? a.source)}</div>
<div style="font-size:15px;font-weight:600;color:#1C1C1E;padding-top:3px">${esc(a.title)}</div>
<div style="font-size:13px;color:#6C6C70;padding-top:2px">Élément surveillé : ${esc(a.watchValue)}</div></td></tr>`,
    )
    .join("");
  return `<!doctype html><html><body style="margin:0;background:#F2F2F7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 12px">
<table width="100%" style="max-width:560px;background:#FFFFFF;border-radius:18px;padding:28px" cellpadding="0" cellspacing="0">
<tr><td style="font-size:22px;font-weight:700;color:#1C1C1E;padding-bottom:6px">Nouvelles alertes de surveillance</td></tr>
<tr><td style="font-size:15px;color:#3A3A3C;padding-bottom:12px">Bonjour ${esc(name || "")}, voici ce qui a été détecté pour vos domaines et marques surveillés.</td></tr>
${rows}
<tr><td style="padding-top:22px"><a href="${esc(appUrl)}/?vue=surveillance" style="display:inline-block;background:#007AFF;color:#FFFFFF;text-decoration:none;font-weight:600;font-size:16px;padding:13px 22px;border-radius:12px">Voir toutes les alertes</a></td></tr>
${alerts.length > sorted.length ? `<tr><td style="font-size:13px;color:#6C6C70;padding-top:12px">Et ${alerts.length - sorted.length} autres alertes dans l’application.</td></tr>` : ""}
</table></td></tr></table></body></html>`;
}

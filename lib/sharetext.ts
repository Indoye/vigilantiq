/** Textes et liens de partage d'une vulnérabilité (utilisables côté navigateur). */
import type { Priority } from "./types.ts";

const PRIO_FR: Record<Priority, string> = { urgente: "urgente", haute: "haute", moyenne: "moyenne", basse: "basse" };

export interface ShareInfo {
  id: string;
  product: string;
  priority: Priority;
  score: number;
  cvss: number | null;
  kev: boolean;
  poc: number;
  summary?: string | null;
}

const fmtCvss = (n: number | null) => (n == null ? null : n.toFixed(1).replace(".", ","));

/** Ligne courte (titre d'e-mail, Reddit). */
export function shareTitle(i: ShareInfo): string {
  return `${i.id} · ${i.product} : priorité ${PRIO_FR[i.priority]} (${i.score}/100)`;
}

/** Message court pour X (≤ 280 caractères avec le lien, compté pour 23). */
export function shareShortText(i: ShareInfo): string {
  const bits = [`score ${i.score}/100`];
  const c = fmtCvss(i.cvss);
  if (c) bits.push(`CVSS ${c}`);
  if (i.kev) bits.push("exploitée (CISA KEV)");
  else if (i.poc > 0) bits.push(`${i.poc} PoC public${i.poc > 1 ? "s" : ""}`);
  let t = `⚠️ ${i.id} – ${i.product} : priorité ${PRIO_FR[i.priority]}, ${bits.join(", ")}.`;
  if (t.length > 230) t = t.slice(0, 229) + "…";
  return `${t} #CVE #cybersécurité`;
}

/** Corps d'e-mail complet. */
export function shareEmailBody(i: ShareInfo, url: string): string {
  const lines = [
    "Bonjour,",
    "",
    `Je vous partage cette vulnérabilité repérée sur VigilantIQ : ${i.id} (${i.product}).`,
    "",
    `• Priorité : ${PRIO_FR[i.priority]} (score ${i.score}/100)`,
  ];
  const c = fmtCvss(i.cvss);
  if (c) lines.push(`• CVSS : ${c}`);
  lines.push(`• Exploitation : ${i.kev ? "active (catalogue CISA KEV)" : i.poc > 0 ? `${i.poc} code${i.poc > 1 ? "s" : ""} d'exploitation public${i.poc > 1 ? "s" : ""}` : "aucun signal connu"}`);
  if (i.summary) lines.push("", i.summary.trim());
  lines.push("", `Fiche complète : ${url}`);
  return lines.join("\n");
}

export type Network = "email" | "linkedin" | "x" | "reddit";

export function networkUrl(n: Network, i: ShareInfo, url: string): string {
  const e = encodeURIComponent;
  switch (n) {
    case "email":
      return `mailto:?subject=${e(shareTitle(i))}&body=${e(shareEmailBody(i, url))}`;
    case "linkedin":
      return `https://www.linkedin.com/sharing/share-offsite/?url=${e(url)}`;
    case "x":
      return `https://x.com/intent/post?text=${e(shareShortText(i))}&url=${e(url)}`;
    case "reddit":
      return `https://www.reddit.com/submit?url=${e(url)}&title=${e(shareTitle(i))}`;
  }
}

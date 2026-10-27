import type { Mention, Priority, Ssvc, Vuln } from "./types.ts";

type ScoreInput = Pick<Vuln, "cvss" | "epss" | "kev"> & {
  ssvc?: Ssvc | null;
  mentions?: Pick<Mention, "kind" | "source">[];
};

/**
 * Score de priorité 0–100, déterministe et explicable.
 * - Gravité (CVSS) : jusqu'à 60 points
 * - Probabilité d'exploitation (EPSS) : jusqu'à 25 points
 * - Exploitation active (CISA KEV, ou SSVC « active ») : +30, rançongiciel +5
 * - Code d'exploitation public (SSVC « poc » ou Exploit-DB) : +10
 * - Alerte d'un CERT ou d'une agence : +5
 * L'IA rédige les explications ; elle ne décide pas du score.
 */
export function scoreVuln(v: ScoreInput): { score: number; priority: Priority; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;

  if (v.cvss != null) {
    score += v.cvss * 6;
    if (v.cvss >= 9) reasons.push(`Gravité critique (CVSS ${v.cvss.toFixed(1)})`);
    else if (v.cvss >= 7) reasons.push(`Gravité élevée (CVSS ${v.cvss.toFixed(1)})`);
  } else {
    score += 30;
    reasons.push("Score CVSS pas encore publié");
  }

  if (v.epss != null) {
    score += Math.sqrt(v.epss) * 25;
    if (v.epss >= 0.1) reasons.push(`${Math.round(v.epss * 100)} % de probabilité d'exploitation sous 30 jours (EPSS)`);
  }

  const activeSsvc = v.ssvc?.exploitation === "active";
  const exploited = Boolean(v.kev) || activeSsvc;
  if (v.kev) {
    score += 30;
    reasons.push("Exploitée activement (catalogue CISA KEV)");
    if (v.kev.ransomware) {
      score += 5;
      reasons.push("Utilisée dans des campagnes de rançongiciel");
    }
  } else if (activeSsvc) {
    score += 30;
    reasons.push("Exploitation active signalée par la CISA (SSVC)");
  }

  const mentions = v.mentions ?? [];
  if (!exploited && (v.ssvc?.exploitation === "poc" || mentions.some((m) => m.kind === "exploit"))) {
    score += 10;
    reasons.push("Code d'exploitation public");
  }
  const alerts = [...new Set(mentions.filter((m) => m.kind === "cert" || m.kind === "gouv").map((m) => m.source))];
  if (alerts.length) {
    score += 5;
    reasons.push(`Signalée par ${alerts.slice(0, 3).join(", ")}`);
  }

  score = Math.min(100, Math.round(score));
  return { score, priority: priorityFor(score, exploited), reasons };
}

export function priorityFor(score: number, exploited: boolean): Priority {
  if (exploited || score >= 75) return "urgente";
  if (score >= 55) return "haute";
  if (score >= 35) return "moyenne";
  return "basse";
}

export const PRIORITY_ORDER: Priority[] = ["urgente", "haute", "moyenne", "basse"];

export const PRIORITY_LABEL: Record<Priority, string> = {
  urgente: "Urgente",
  haute: "Haute",
  moyenne: "Moyenne",
  basse: "Basse",
};

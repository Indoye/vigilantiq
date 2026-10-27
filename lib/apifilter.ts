/** Filtres de l'API v1 sur le flux du jour. Sans dépendance : testable directement. */
import { PRIORITY_ORDER } from "./score.ts";
import { matchStack, parseStack } from "./stack.ts";
import type { Priority, Vuln } from "./types.ts";

export interface VulnQuery {
  priorities: Priority[] | null;
  exploited: boolean | null;
  poc: boolean | null;
  stack: string[];
  q: string;
  since: number | null;
  limit: number;
}

const bool = (v: string | null): boolean | null => (v == null || v === "" ? null : ["1", "true", "oui", "yes"].includes(v.toLowerCase()));

export function parseVulnQuery(sp: URLSearchParams): VulnQuery | { error: string } {
  let priorities: Priority[] | null = null;
  const p = sp.get("priority");
  if (p) {
    const list = p.split(",").map((s) => s.trim().toLowerCase());
    const bad = list.filter((x) => !(PRIORITY_ORDER as string[]).includes(x));
    if (bad.length) return { error: `Priorité inconnue : ${bad.join(", ")} (valeurs : ${PRIORITY_ORDER.join(", ")})` };
    priorities = list as Priority[];
  }
  // min_priority=haute → urgente + haute
  const min = sp.get("min_priority");
  if (min) {
    const i = PRIORITY_ORDER.indexOf(min.toLowerCase() as Priority);
    if (i < 0) return { error: `min_priority inconnue : ${min}` };
    priorities = PRIORITY_ORDER.slice(0, i + 1);
  }
  let since: number | null = null;
  const s = sp.get("since");
  if (s) {
    since = Date.parse(s);
    if (Number.isNaN(since)) return { error: "since doit être une date ISO 8601, par ex. 2026-10-27T00:00:00Z" };
  }
  const limit = Math.min(1000, Math.max(1, Number(sp.get("limit") || 500) || 500));
  return {
    priorities,
    exploited: bool(sp.get("exploited")),
    poc: bool(sp.get("poc")),
    stack: parseStack(sp.get("stack") ?? ""),
    q: (sp.get("q") ?? "").trim().toLowerCase(),
    since,
    limit,
  };
}

export function filterVulns(vulns: Vuln[], f: VulnQuery): Vuln[] {
  return vulns
    .filter((v) => {
      if (f.priorities && !f.priorities.includes(v.priority)) return false;
      const exploited = Boolean(v.kev) || v.ssvc?.exploitation === "active";
      if (f.exploited != null && exploited !== f.exploited) return false;
      const hasPoc = (v.exploits?.length ?? 0) > 0 || v.mentions.some((m) => m.kind === "exploit");
      if (f.poc != null && hasPoc !== f.poc) return false;
      if (f.stack.length && matchStack(v, f.stack).length === 0) return false;
      if (f.since != null && !(Date.parse(v.published) >= f.since)) return false;
      if (f.q) {
        const hay = `${v.id} ${v.description} ${v.products.join(" ")} ${v.vendors.join(" ")} ${v.affected.map((a) => a.product).join(" ")}`.toLowerCase();
        if (!hay.includes(f.q)) return false;
      }
      return true;
    })
    .slice(0, f.limit);
}

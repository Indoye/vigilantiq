/**
 * Écosystème des attaques d'un pays (par défaut le Sénégal) : aperçu pour la mini-carte.
 *
 * - Cloudflare Radar (CLOUDFLARE_API_TOKEN) : pays d'origine des attaques visant le pays et pays visés depuis le pays
 *   (L7 et L3), protections déclenchées, secteurs visés, coupures Internet.
 * - ransomware.live : organisations du pays revendiquées par des groupes de rançongiciels.
 * - abuse.ch Feodo Tracker : serveurs de commande de botnets hébergés dans le pays.
 * - OpenPhish (et URLhaus/ThreatFox avec clé) : URL malveillantes hébergées sous le domaine national (.sn).
 * - Have I Been Pwned : fuites publiques de services du domaine national.
 *
 * Chaque source est indépendante : une source en panne n'empêche pas les autres de s'afficher.
 */
import type { RansomVictim } from "./cti/sources.ts";
import type { Layer, Period } from "./threatmap.ts";

export interface Share {
  key: string;
  value: number;
}

export interface Outage {
  start: string;
  end: string | null;
  cause: string;
  type: string;
  description: string;
  networks: string[];
}

export interface FocusData {
  cc: string;
  tld: string;
  period: Period;
  generatedAt: string;
  radar: {
    configured: boolean;
    start: string | null;
    end: string | null;
    /** Pays d'où partent les attaques qui visent le pays (part du trafic d'attaque, %) */
    incoming: { cc: string; value: number; layer: Layer }[];
    /** Pays visés par des attaques parties du pays */
    outgoing: { cc: string; value: number; layer: Layer }[];
    products: Share[];
    industries: Share[];
    outages: Outage[];
  };
  ransomware: { total: number; last12m: number; victims: Pick<RansomVictim, "victim" | "group" | "sector" | "discovered" | "domain">[]; groups: Share[] };
  c2: { count: number; online: number; malware: Share[] };
  phishing: { count: number; hosts: string[]; threats: Share[] };
  breaches: { count: number; items: { title: string; domain: string; date: string | null; pwnCount: number }[] };
  sources: { name: string; ok: boolean; detail?: string }[];
}

/** Regroupe les paires d'attaque par pays partenaire (origines des attaques entrantes, cibles des sortantes). */
export function splitPairs(pairs: { from: string; to: string; value: number; layer: Layer }[], cc: string) {
  const sum = (list: { key: string; value: number; layer: Layer }[]) => {
    const m = new Map<string, { cc: string; value: number; layer: Layer }>();
    for (const x of list) {
      const k = `${x.layer}:${x.key}`;
      const prev = m.get(k);
      if (!prev || x.value > prev.value) m.set(k, { cc: x.key, value: x.value, layer: x.layer });
    }
    return [...m.values()].sort((a, b) => b.value - a.value);
  };
  return {
    incoming: sum(pairs.filter((p) => p.to === cc && p.from !== cc).map((p) => ({ key: p.from, value: p.value, layer: p.layer }))),
    outgoing: sum(pairs.filter((p) => p.from === cc && p.to !== cc).map((p) => ({ key: p.to, value: p.value, layer: p.layer }))),
  };
}

/** Résumé Radar « summary_0 » → parts triées (hors « other »). */
export function parseSummary(result: unknown): Share[] {
  const s = (result as { summary_0?: Record<string, unknown> } | null)?.summary_0 ?? {};
  return Object.entries(s)
    .map(([key, v]) => ({ key, value: Number(v) }))
    .filter((x) => x.key.toLowerCase() !== "other" && Number.isFinite(x.value) && x.value > 0)
    .sort((a, b) => b.value - a.value);
}

export function parseOutages(result: unknown, cc: string): Outage[] {
  const list = ((result as { annotations?: unknown[] } | null)?.annotations ?? []) as Record<string, unknown>[];
  return list
    .filter((a) => !Array.isArray(a.locations) || (a.locations as string[]).length === 0 || (a.locations as string[]).map((x) => String(x).toUpperCase()).includes(cc))
    .map((a) => {
      const o = (a.outage ?? {}) as Record<string, unknown>;
      const asns = Array.isArray(a.asnsDetails) ? (a.asnsDetails as Record<string, unknown>[]) : [];
      return {
        start: String(a.startDate ?? ""),
        end: a.endDate ? String(a.endDate) : null,
        cause: String(o.outageCause ?? ""),
        type: String(o.outageType ?? ""),
        description: String(a.description ?? "").slice(0, 300),
        networks: asns.map((x) => String(x.name ?? x.asn ?? "")).filter(Boolean).slice(0, 4),
      };
    })
    .filter((o) => o.start)
    .sort((a, b) => b.start.localeCompare(a.start))
    .slice(0, 6);
}


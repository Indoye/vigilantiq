/**
 * Typosquatting : variantes d'un domaine (fautes de frappe, caractères ressemblants, autres extensions,
 * mots-clés d'hameçonnage) puis vérification DNS (DNS-over-HTTPS, Cloudflare) pour garder celles qui existent.
 */
import { brandOf } from "./sources.ts";

const KEYBOARD: Record<string, string> = {
  a: "qzsw", b: "vghn", c: "xdfv", d: "serfcx", e: "wsdr", f: "drtgvc", g: "ftyhbv", h: "gyujnb", i: "ujko", j: "huikmn",
  k: "jiolm", l: "kopm", m: "njkl", n: "bhjm", o: "iklp", p: "olm", q: "wa", r: "edft", s: "awedxz", t: "rfgy",
  u: "yhji", v: "cfgb", w: "qase", x: "zsdc", y: "tghu", z: "asx",
  "0": "9o", "1": "2l", "2": "13", "3": "24", "4": "35", "5": "46", "6": "57", "7": "68", "8": "79", "9": "80",
};
const HOMOGLYPHS: Record<string, string[]> = {
  o: ["0"], "0": ["o"], l: ["1", "i"], i: ["1", "l"], "1": ["l", "i"], e: ["3"], a: ["4"], s: ["5"], b: ["8"], g: ["9", "q"],
  m: ["rn"], w: ["vv"], d: ["cl"], n: ["m"], u: ["v"], v: ["u"],
};
const TLDS = ["com", "net", "org", "info", "co", "io", "online", "site", "xyz", "app", "live", "support", "biz", "me"];
const WORDS = ["login", "secure", "support", "account", "online", "mail", "portal", "verify", "auth", "app"];

/** Variantes candidates (sans le domaine d'origine), au plus `max`, les plus probables d'abord. */
export function permutations(domain: string, max = 140): string[] {
  const name = brandOf(domain);
  const idx = domain.lastIndexOf(name);
  const prefix = domain.slice(0, idx); // sous-domaines éventuels (rare)
  const suffix = domain.slice(idx + name.length); // « .sn », « .co.uk »
  const tld = suffix.replace(/^\./, "");
  const out: string[] = [];
  const add = (n: string, sfx = suffix) => {
    if (!n || n.length < 2 || n.startsWith("-") || n.endsWith("-") || !/^[a-z0-9-]+$/.test(n)) return;
    out.push(`${prefix}${n}${sfx}`);
  };
  // Autres extensions (souvent enregistrées en premier par les fraudeurs)
  for (const t of TLDS) if (t !== tld) add(name, `.${t}`);
  // Caractères ressemblants
  for (let i = 0; i < name.length; i++) for (const g of HOMOGLYPHS[name[i]] ?? []) add(name.slice(0, i) + g + name.slice(i + 1));
  // Omission, répétition, inversion
  for (let i = 0; i < name.length; i++) {
    add(name.slice(0, i) + name.slice(i + 1));
    add(name.slice(0, i) + name[i] + name.slice(i));
    if (i < name.length - 1) add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2));
  }
  // Mots-clés d'hameçonnage
  for (const w of WORDS) {
    add(`${name}-${w}`);
    add(`${w}-${name}`);
  }
  // Touches voisines
  for (let i = 0; i < name.length; i++) for (const k of KEYBOARD[name[i]] ?? "") add(name.slice(0, i) + k + name.slice(i + 1));
  // Trait d'union inséré
  for (let i = 1; i < name.length; i++) add(`${name.slice(0, i)}-${name.slice(i)}`);
  return [...new Set(out)].filter((d) => d !== domain).slice(0, max);
}

export interface Lookalike {
  domain: string;
  ips: string[];
  mx: boolean;
}

async function doh(name: string, type: "A" | "MX"): Promise<{ status: number; answers: string[] }> {
  const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { Accept: "application/dns-json" },
    signal: AbortSignal.timeout(8000),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`DNS HTTP ${res.status}`);
  const j = (await res.json()) as { Status?: number; Answer?: { type: number; data: string }[] };
  return { status: j.Status ?? -1, answers: (j.Answer ?? []).filter((a) => (type === "A" ? a.type === 1 : a.type === 15)).map((a) => a.data) };
}

/** Variantes enregistrées et actives (adresse IP ou serveur de messagerie). */
export async function findLookalikes(domain: string, max = 140): Promise<Lookalike[]> {
  const list = permutations(domain, max);
  const found: Lookalike[] = [];
  let errors = 0;
  for (let i = 0; i < list.length; i += 12) {
    const chunk = list.slice(i, i + 12);
    const res = await Promise.allSettled(
      chunk.map(async (d) => {
        const a = await doh(d, "A");
        const mx = await doh(d, "MX").catch(() => ({ status: -1, answers: [] as string[] }));
        if (a.answers.length || mx.answers.length) return { domain: d, ips: a.answers.slice(0, 4), mx: mx.answers.length > 0 };
        return null;
      }),
    );
    for (const r of res) {
      if (r.status === "fulfilled" && r.value) found.push(r.value);
      else if (r.status === "rejected") errors++;
    }
    if (errors > 20) throw new Error("résolution DNS indisponible");
  }
  return found;
}

/** Correspondance logiciel → produit CPE : fonctions pures (normalisation, score), testées isolément. */

export const MIN_CONFIDENCE = 72;

const STOP = new Set(["the", "for", "and", "of", "x64", "x86", "64", "32", "bit", "bits", "edition", "version", "update", "setup", "installer", "client", "desktop", "app", "application", "inc", "corp", "corporation", "ltd", "llc", "gmbh", "sa", "sas", "software", "co"]);

/** Nom normalisé, clé de cache : « Zoom Workplace (64-bit) 6.2.5 » → « zoom workplace ». */
export function normalizeName(displayName: string): string {
  return displayName
    .toLowerCase()
    .replace(/[®™©]/g, "")
    .replace(/\((?:x64|x86|64[- ]?bit|32[- ]?bit|user|machine|[^)]*\d+\.\d+[^)]*)\)/g, " ")
    .replace(/\b(?:x64|x86|amd64|arm64|64[- ]?bit|32[- ]?bit|win(?:dows)?\s?(?:x64|32|64))\b/g, " ")
    .replace(/\bv?\d+(?:[._-]\d+)+[a-z0-9.-]*\b/g, " ")
    .replace(/\b(?:en-us|fr-fr|multilingual|mui)\b/g, " ")
    .replace(/[^a-z0-9+#.]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export const tokens = (s: string) =>
  s
    .toLowerCase()
    .split(/[^a-z0-9+#]+/)
    .filter((t) => t.length >= 2 && !STOP.has(t) && !/^\d+$/.test(t));

export interface CpeCandidate {
  vendor: string;
  product: string;
  title: string;
}

/** Retire la version et l'éditeur redondant d'un titre CPE (« Google Chrome 120.0.6099.71 » → « google chrome »). */
const titleBase = (t: string) => normalizeName(t);

/**
 * Meilleur produit parmi les candidats. Score = recouvrement des mots du nom et du titre CPE (dans les deux sens),
 * bonus si l'éditeur installé correspond au vendeur CPE, malus si le titre contient des mots absents du nom.
 */
export function bestCandidate(name: string, publisher: string, cands: CpeCandidate[]): { vendor: string; product: string; confidence: number; title: string } | null {
  const nt = new Set(tokens(normalizeName(name)));
  if (!nt.size) return null;
  const pub = new Set(tokens(publisher));
  const byProduct = new Map<string, { c: CpeCandidate; score: number }>();
  for (const c of cands) {
    const tt = new Set([...tokens(titleBase(c.title)), ...tokens(c.product.replace(/_/g, " "))]);
    const vt = new Set(tokens(c.vendor.replace(/[_-]/g, " ")));
    // Le vendeur dans le titre ne doit pas compter comme un mot « en trop »
    // (si le produit porte le nom de l'éditeur, comme « python », on garde tous les mots)
    const titleRest = [...tt].filter((t) => !vt.has(t));
    const titleOnly = titleRest.length ? titleRest : [...tt];
    const nameRest = [...nt].filter((t) => !vt.has(t) && !pub.has(t));
    const nameOnly = nameRest.length ? nameRest : [...nt];
    const common = nameOnly.filter((t) => tt.has(t)).length;
    if (!common) continue;
    const recall = common / Math.max(1, nameOnly.length);
    const precision = common / Math.max(1, titleOnly.length);
    let score = 0.6 * recall + 0.4 * precision;
    const vendorHit = [...vt].some((t) => pub.has(t) || nt.has(t));
    score += vendorHit ? 0.15 : pub.size ? -0.1 : 0;
    const k = `${c.vendor}:${c.product}`;
    const prev = byProduct.get(k);
    if (!prev || score > prev.score) byProduct.set(k, { c, score });
  }
  const best = [...byProduct.values()].sort((a, b) => b.score - a.score)[0];
  if (!best) return null;
  const confidence = Math.max(0, Math.min(100, Math.round(best.score * 100)));
  return { vendor: best.c.vendor, product: best.c.product, confidence, title: best.c.title.replace(/\s+[\d.]+.*$/, "") };
}


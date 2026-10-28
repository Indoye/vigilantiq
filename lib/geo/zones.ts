/**
 * Pays et zones géographiques de la ThreatMap.
 * Données pays : mledoze/countries (ODbL 1.0), extraites dans countries.json.
 */
import data from "./countries.json" with { type: "json" };

export interface Country {
  cca2: string;
  ccn3: string;
  name: string;
  region: string;
  sub: string;
  lat: number;
  lng: number;
}

export const COUNTRIES: Country[] = (data.rows as [string, string, string, string, string, number, number][]).map(
  ([cca2, ccn3, name, region, sub, lat, lng]) => ({ cca2, ccn3, name, region, sub, lat, lng }),
);
export const BY_CC = new Map(COUNTRIES.map((c) => [c.cca2, c]));
export const BY_NUM = new Map(COUNTRIES.filter((c) => c.ccn3).map((c) => [c.ccn3, c]));

export interface Zone {
  id: string;
  label: string;
  /** Pays membres : région ou sous-région */
  match: (c: Country) => boolean;
}

export const ZONES: Zone[] = [
  { id: "monde", label: "Monde", match: () => true },
  { id: "europe", label: "Europe", match: (c) => c.region === "europe" },
  { id: "afrique", label: "Afrique", match: (c) => c.region === "afrique" },
  { id: "afrique-ouest", label: "Afrique de l’Ouest", match: (c) => c.sub === "afrique-ouest" },
  { id: "afrique-nord", label: "Afrique du Nord", match: (c) => c.sub === "afrique-nord" },
  { id: "afrique-centrale-est", label: "Afrique centrale et de l’Est", match: (c) => c.sub === "afrique-centrale" || c.sub === "afrique-est" },
  { id: "afrique-australe", label: "Afrique australe", match: (c) => c.sub === "afrique-australe" },
  { id: "moyen-orient", label: "Moyen-Orient", match: (c) => c.sub === "moyen-orient" },
  { id: "amerique-nord", label: "Amérique du Nord", match: (c) => c.sub === "amerique-nord" },
  { id: "amerique-latine", label: "Amérique latine et Caraïbes", match: (c) => c.sub === "amerique-latine" },
  { id: "asie", label: "Asie (hors Moyen-Orient)", match: (c) => c.region === "asie" && c.sub !== "moyen-orient" },
  { id: "oceanie", label: "Océanie", match: (c) => c.region === "oceanie" },
];

/** Codes ISO alpha-2 d'une zone (« monde » = tous) ou d'un pays (« pays:SN »). */
export function zoneMembers(zoneId: string): Set<string> | null {
  if (zoneId === "monde") return null;
  if (zoneId.startsWith("pays:")) return new Set([zoneId.slice(5).toUpperCase()]);
  const z = ZONES.find((x) => x.id === zoneId);
  return z ? new Set(COUNTRIES.filter(z.match).map((c) => c.cca2)) : null;
}

export function zoneLabel(zoneId: string): string {
  if (zoneId.startsWith("pays:")) return BY_CC.get(zoneId.slice(5).toUpperCase())?.name ?? zoneId.slice(5);
  return ZONES.find((z) => z.id === zoneId)?.label ?? "Monde";
}

export const countryName = (cc: string) => BY_CC.get(cc.toUpperCase())?.name ?? cc.toUpperCase();

/** Drapeau emoji à partir du code alpha-2. */
export function flag(cc: string): string {
  if (!/^[A-Za-z]{2}$/.test(cc)) return "🏳️";
  return String.fromCodePoint(...cc.toUpperCase().split("").map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}

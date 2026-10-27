import type { Vuln } from "./types.ts";

export function pct(e: number | null | undefined): string {
  if (e == null) return "–";
  const p = e * 100;
  const s = p < 1 ? p.toFixed(2) : p < 10 ? p.toFixed(1) : p.toFixed(0);
  return `${s.replace(".", ",")} %`;
}

export function cvssFr(c: number | null | undefined): string {
  return c == null ? "–" : c.toFixed(1).replace(".", ",");
}

export function relTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "à l’instant";
  const m = Math.round(s / 60);
  if (m < 60) return `il y a ${m} min`;
  const h = Math.round(m / 60);
  if (h < 24) return `il y a ${h} h`;
  const d = Math.round(h / 24);
  if (d < 30) return `il y a ${d} j`;
  return dateFr(iso);
}

export function dateFr(iso: string | null | undefined, withYear = false): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  return new Date(t).toLocaleDateString("fr-FR", {
    day: "numeric",
    month: "long",
    ...(withYear ? { year: "numeric" } : {}),
    timeZone: "UTC",
  });
}

export function timeFr(iso: string): string {
  return new Date(iso).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
}

function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/\b([a-z])/g, (c) => c.toUpperCase());
}

/** Nom lisible du produit principal. */
export function productName(v: Pick<Vuln, "affected" | "products" | "vendors" | "kev">): string {
  if (v.kev?.name && !v.affected.length && !v.products.length) return v.kev.name;
  const a = v.affected[0];
  if (a) return a.source === "CNA" ? a.product : titleCase(a.product);
  if (v.products[0]) return titleCase(v.products[0]);
  if (v.vendors[0]) return titleCase(v.vendors[0]);
  return "Produit non précisé";
}

export function vendorName(v: Pick<Vuln, "affected" | "vendors">): string {
  const a = v.affected.find((x) => x.vendor);
  if (a) return a.source === "CNA" ? a.vendor : titleCase(a.vendor);
  return v.vendors[0] ? titleCase(v.vendors[0]) : "";
}

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "Lien";
  }
}

export const SSVC_FR: Record<string, string> = {
  active: "active",
  poc: "preuve de concept publique",
  none: "aucune connue",
  yes: "oui",
  no: "non",
  total: "total",
  partial: "partiel",
};

import type { Vuln } from "./types.ts";

/** Transforme "nginx, Fortinet\nwordpress" en ["nginx", "fortinet", "wordpress"]. */
export function parseStack(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[,\n;]+/)
        .map((s) => s.trim().toLowerCase())
        .filter((s) => s.length >= 2),
    ),
  );
}

function normalize(s: string): string {
  return s.toLowerCase().replace(/[_\-]+/g, " ");
}

/** Renvoie les mots-clés de la stack qui concernent cette vulnérabilité. */
export function matchStack(v: Pick<Vuln, "vendors" | "products" | "description">, stack: string[]): string[] {
  if (stack.length === 0) return [];
  const cpe = [...v.vendors, ...v.products].map(normalize);
  const text = normalize(v.description);
  return stack.filter((kw) => {
    const k = normalize(kw);
    if (cpe.some((c) => c === k || c.includes(k))) return true;
    const escaped = k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`).test(text);
  });
}
